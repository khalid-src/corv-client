package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifyChecksum(t *testing.T) {
	data := []byte("corv binary bytes")
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	asset := "corv-linux-amd64"
	// sha256sum -b format: "<hash> *<name>", plus an unrelated line.
	sums := []byte(fmt.Sprintf("deadbeef *%s.backup\ndeadbeef *corv-darwin-arm64\n%s *%s\n", asset, hash, asset))

	if err := verifyChecksum(data, sums, asset); err != nil {
		t.Fatalf("valid checksum rejected: %v", err)
	}
	if err := verifyChecksum([]byte("tampered"), sums, asset); err == nil {
		t.Fatal("mismatched checksum accepted")
	}
	if err := verifyChecksum(data, sums, "corv-windows-amd64.exe"); err == nil {
		t.Fatal("missing asset accepted")
	}
}

func TestHTTPGetRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("123456789"))
	}))
	defer server.Close()
	if _, err := httpGet(server.URL, 8); err == nil {
		t.Fatal("expected oversized response error")
	}
}

func TestUninstallReportsExecutableRemovalFailure(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	originalRemove := removeExecutablePath
	removeExecutablePath = func(string) error { return errors.New("access denied") }
	t.Cleanup(func() { removeExecutablePath = originalRemove })

	var stdout, stderr bytes.Buffer
	if code := cmdUninstall(nil, &stdout, &stderr); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(stdout.String(), "Corv uninstalled") || !strings.Contains(stderr.String(), "remove the binary manually") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestUninstallReportsDataRemovalFailure(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	originalRemoveExecutable := removeExecutablePath
	originalRemoveAll := removeAllData
	removeExecutablePath = func(string) error { return nil }
	removeAllData = func(string) error { return errors.New("access denied") }
	t.Cleanup(func() {
		removeExecutablePath = originalRemoveExecutable
		removeAllData = originalRemoveAll
	})

	var stdout, stderr bytes.Buffer
	if code := cmdUninstall([]string{"--purge"}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(stdout.String(), "Corv uninstalled") || !strings.Contains(stderr.String(), "could not remove data dir") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestParseTagFromLocation(t *testing.T) {
	got, err := parseTagFromLocation("https://github.com/o/r/releases/tag/v1.2.3")
	if err != nil || got != "v1.2.3" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := parseTagFromLocation("https://github.com/o/r/releases"); err == nil {
		t.Fatal("expected error when no release tag in URL")
	}
}

func TestAssetNameMatchesPlatform(t *testing.T) {
	want := "corv-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	if got := assetName(); got != want {
		t.Fatalf("assetName() = %q, want %q", got, want)
	}
}

func TestReplaceFileSwapsContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corv")
	if err := os.WriteFile(path, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(path, []byte("NEW")); err != nil {
		t.Fatalf("replaceFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "NEW" {
		t.Fatalf("content = %q, want NEW", got)
	}
}

func TestReplaceFileWriteErrorIsPlatformNeutral(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	err := replaceFile(filepath.Join(dir, "corv"), []byte("NEW"))
	if err == nil {
		t.Fatal("expected write failure")
	}
	message := err.Error()
	if strings.Contains(strings.ToLower(message), "sudo") || !strings.Contains(message, "writable location") {
		t.Fatalf("write error = %q", message)
	}
}
