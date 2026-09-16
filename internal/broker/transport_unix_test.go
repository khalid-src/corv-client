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

func TestListenBrokerEnforcesOwnerOnlyPermissions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CORV_HOME", home)
	runDir := filepath.Join(home, "run")
	if err := os.MkdirAll(runDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runDir, 0o777); err != nil {
		t.Fatal(err)
	}

	ln, addr, err := listenBroker()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		cleanupBroker(addr)
	})

	dirInfo, err := os.Stat(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("run directory mode = %o, want 700", got)
	}
	socketInfo, err := os.Stat(addr)
	if err != nil {
		t.Fatal(err)
	}
	if got := socketInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode = %o, want 600", got)
	}
}
