//go:build !windows

package broker

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRemoteSweepKeepsSilentRunAndRemovesCompletedRun(t *testing.T) {
	uid, err := exec.Command("id", "-u").Output()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dir := filepath.Join(root, "corv-jobs-"+strings.TrimSpace(string(uid)))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := fmt.Sprintf("%016x-test", time.Now().Add(-2*jobTTL).Unix())
	for _, suffix := range []string{".sh", ".log"} {
		if err := os.WriteFile(filepath.Join(dir, old+"-silent"+suffix), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, suffix := range []string{".sh", ".log", ".rc"} {
		if err := os.WriteFile(filepath.Join(dir, old+"-done"+suffix), []byte("0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.Command("sh", "-c", sweepRemoteCommand())
	cmd.Env = append(os.Environ(), "TMPDIR="+root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sweep: %v: %s", err, out)
	}
	for _, suffix := range []string{".sh", ".log"} {
		if _, err := os.Stat(filepath.Join(dir, old+"-silent"+suffix)); err != nil {
			t.Fatalf("silent run %s removed: %v", suffix, err)
		}
	}
	for _, suffix := range []string{".sh", ".log", ".rc"} {
		if _, err := os.Stat(filepath.Join(dir, old+"-done"+suffix)); !os.IsNotExist(err) {
			t.Fatalf("completed run %s remains: %v", suffix, err)
		}
	}
}
