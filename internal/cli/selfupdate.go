package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/khalid-src/corv-client/internal/broker"
	"github.com/khalid-src/corv-client/internal/paths"
	"github.com/khalid-src/corv-client/internal/version"
)

const repoSlug = "khalid-src/corv-client"

const (
	maxReleaseBinaryBytes = 100 << 20
	maxChecksumBytes      = 1 << 20
)

var (
	removeExecutablePath = removeExecutable
	removeAllData        = os.RemoveAll
	renameUpdateFile     = os.Rename
)

// cmdUpdate downloads the latest released binary for this platform, verifies its
// SHA-256 checksum, and replaces the running executable in place. It runs only
// when the user types `corv update`; Corv never updates itself in the background.
func cmdUpdate(args []string, stdout, stderr io.Writer) int {
	for _, a := range args {
		return fail(stderr, fmt.Errorf("unexpected argument: %s", a))
	}

	latest, err := latestReleaseTag()
	if err != nil {
		return fail(stderr, fmt.Errorf("check latest version: %w", err))
	}
	if version.Version == latest {
		fmt.Fprintf(stdout, "corv is already up to date (%s)\n", latest)
		return 0
	}

	asset := assetName()
	base := "https://github.com/" + repoSlug + "/releases/latest/download"
	fmt.Fprintf(stdout, "Updating corv %s -> %s ...\n", version.Version, latest)

	bin, err := httpGet(base+"/"+asset, maxReleaseBinaryBytes)
	if err != nil {
		return fail(stderr, fmt.Errorf("download %s: %w", asset, err))
	}
	sums, err := httpGet(base+"/SHA256SUMS", maxChecksumBytes)
	if err != nil {
		return fail(stderr, fmt.Errorf("download checksums: %w", err))
	}
	if err := verifyChecksum(bin, sums, asset); err != nil {
		return fail(stderr, err)
	}
	if err := replaceExecutable(bin); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Updated to %s. The broker restarts itself on the next command.\n", latest)
	return 0
}

// cmdUninstall stops the broker and removes the corv binary. Saved connections
// and logs are kept unless --purge is given.
func cmdUninstall(args []string, stdout, stderr io.Writer) int {
	purge := false
	for _, a := range args {
		switch a {
		case "--purge":
			purge = true
		default:
			return fail(stderr, fmt.Errorf("unexpected argument: %s", a))
		}
	}

	self, _ := os.Executable()
	_ = broker.NewClient(self).Shutdown()

	p, perr := paths.Default()
	var purgeErr error
	if purge && perr == nil {
		if purgeErr = removeAllData(p.Root); purgeErr != nil {
			fmt.Fprintf(stderr, "corv: could not remove data dir %s: %v\n", p.Root, purgeErr)
		} else {
			fmt.Fprintf(stdout, "Removed Corv data (%s)\n", p.Root)
		}
	} else if purge && perr != nil {
		purgeErr = perr
		fmt.Fprintf(stderr, "corv: could not resolve the data directory: %v\n", perr)
	}

	exe := self
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	removeErr := removeExecutablePath(exe)
	if removeErr != nil {
		fmt.Fprintf(stderr, "corv: remove the binary manually: %s (%v)\n", exe, removeErr)
	} else if runtime.GOOS == "windows" {
		fmt.Fprintf(stdout, "Removed corv from PATH (a leftover %s.old can be deleted).\n", filepath.Base(exe))
	} else {
		fmt.Fprintf(stdout, "Removed %s\n", exe)
	}

	if !purge && perr == nil {
		fmt.Fprintf(stdout, "Saved connections and logs are kept in %s (use `corv uninstall --purge` to remove them).\n", p.Root)
	}
	if removeErr != nil || purgeErr != nil {
		return 1
	}
	fmt.Fprintln(stdout, "Corv uninstalled.")
	return 0
}

// assetName is the release asset for the running platform, matching the names
// produced by the release workflow.
func assetName() string {
	name := fmt.Sprintf("corv-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// latestReleaseTag reads the tag the /releases/latest URL redirects to, avoiding
// the API (no token, no rate limit, no JSON).
func latestReleaseTag() (string, error) {
	client := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get("https://github.com/" + repoSlug + "/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return parseTagFromLocation(resp.Header.Get("Location"))
}

func parseTagFromLocation(loc string) (string, error) {
	const marker = "/releases/tag/"
	i := strings.Index(loc, marker)
	if i < 0 {
		return "", errors.New("no published release found")
	}
	tag := strings.TrimSpace(loc[i+len(marker):])
	if tag == "" {
		return "", errors.New("could not parse the latest release tag")
	}
	return tag, nil
}

func httpGet(url string, maxBytes int64) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s: response exceeds %d bytes", url, maxBytes)
	}
	return data, nil
}

// verifyChecksum confirms data matches the SHA-256 recorded for asset in a
// sha256sum-format SHA256SUMS file.
func verifyChecksum(data, sums []byte, asset string) error {
	want := ""
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != asset {
			continue
		}
		want = fields[0]
		break
	}
	if want == "" {
		return fmt.Errorf("no checksum recorded for %s", asset)
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
		return fmt.Errorf("checksum mismatch for %s; aborting update", asset)
	}
	return nil
}

// replaceExecutable atomically swaps the running binary for data. On Windows a
// running executable cannot be overwritten, so it is renamed aside first and the
// swap is rolled back on failure.
func replaceExecutable(data []byte) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return replaceFile(exe, data)
}

// replaceFile swaps the file at exe for data via a same-directory temp file and
// rename, rolling back on Windows where the original cannot be overwritten.
func replaceFile(exe string, data []byte) error {
	dir := filepath.Dir(exe)

	tmp, err := os.CreateTemp(dir, ".corv-update-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s; install Corv in a writable location or run with permission to modify this installation: %w", dir, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if runtime.GOOS == "windows" {
		return replaceWindowsFile(exe, tmpName)
	}

	if err := renameUpdateFile(tmpName, exe); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("replace executable: %w", err)
	}
	return nil
}

func replaceWindowsFile(exe, replacement string) error {
	old := exe + ".old"
	_ = os.Remove(old)
	if err := renameUpdateFile(exe, old); err != nil {
		os.Remove(replacement)
		return fmt.Errorf("replace executable: %w", err)
	}
	if err := renameUpdateFile(replacement, exe); err != nil {
		rollbackErr := renameUpdateFile(old, exe)
		os.Remove(replacement)
		if rollbackErr != nil {
			return errors.Join(fmt.Errorf("replace executable: %w", err), fmt.Errorf("restore previous executable: %w", rollbackErr))
		}
		return fmt.Errorf("replace executable: %w", err)
	}
	return nil
}

func removeExecutable(exe string) error {
	if runtime.GOOS == "windows" {
		// A running executable cannot be deleted on Windows; rename it aside so
		// it is gone from PATH.
		old := exe + ".old"
		_ = os.Remove(old)
		return os.Rename(exe, old)
	}
	return os.Remove(exe)
}

// cleanupOldExecutable removes the .old file left by a Windows in-place update.
// Best-effort: it is fine if the file is absent or still locked.
func cleanupOldExecutable() {
	if runtime.GOOS != "windows" {
		return
	}
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe + ".old")
	}
}
