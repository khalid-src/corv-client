//go:build !windows

package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/khalid-src/corv-client/internal/paths"
)

func listenBroker() (net.Listener, string, error) {
	p, err := paths.Default()
	if err != nil {
		return nil, "", err
	}
	runDir := filepath.Join(p.Root, "run")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return nil, "", err
	}
	addr := filepath.Join(runDir, "broker.sock")
	// Unix socket paths are length-limited (~104 bytes on macOS, ~108 on Linux).
	// When the Corv home is deep (e.g. a long temp dir), fall back to a short,
	// per-home path under the system temp dir. The endpoint file records whichever
	// address is used, so clients still find the broker.
	if len(addr) > 100 {
		addr, err = shortSocketPath(p.Root)
		if err != nil {
			return nil, "", err
		}
	}
	_ = os.Remove(addr)
	ln, err := net.Listen("unix", addr)
	if err != nil {
		return nil, "", err
	}
	return ln, addr, nil
}

func shortSocketPath(root string) (string, error) {
	sum := sha256.Sum256([]byte(root))
	name := "corv-" + hex.EncodeToString(sum[:8])
	bases := []string{}
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		bases = append(bases, runtimeDir)
	}
	bases = append(bases, os.TempDir())
	for _, base := range bases {
		dir := filepath.Join(base, name)
		addr := filepath.Join(dir, "broker.sock")
		if len(addr) > 100 {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			continue
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			continue
		}
		return addr, nil
	}
	return "", fmt.Errorf("no safe path is short enough for the broker socket")
}

func dialBroker(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", addr, timeout)
}

func cleanupBroker(addr string) {
	if addr != "" {
		_ = os.Remove(addr)
	}
}
