//go:build !windows

package broker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShortSocketPathPrefersPrivateRuntimeDirectory(t *testing.T) {
	// Use a short runtime dir: t.TempDir() embeds the long test name, which would
	// itself push the socket path past the ~104-byte Unix limit and trip
	// shortSocketPath's length fallback (defeating what this test checks).
	runtimeDir, err := os.MkdirTemp("", "rt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	addr, err := shortSocketPath(strings.Repeat("long-root-", 20))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(addr, runtimeDir+string(filepath.Separator)) {
		t.Fatalf("socket path = %q, runtime dir = %q", addr, runtimeDir)
	}
	info, err := os.Stat(filepath.Dir(addr))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("runtime directory mode = %o", info.Mode().Perm())
	}
}
