//go:build !windows

package broker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShortSocketPathPrefersPrivateRuntimeDirectory(t *testing.T) {
	runtimeDir := t.TempDir()
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
