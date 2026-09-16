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
	now := time.Now()
	uid, err := exec.Command("id", "-u").Output()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dir := filepath.Join(root, "corv-jobs-"+strings.TrimSpace(string(uid)))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := fmt.Sprintf("%016x-test", now.Add(-2*jobTTL).Unix())
	for _, suffix := range []string{".sh", ".log"} {
		if err := os.WriteFile(filepath.Join(dir, old+"-silent"+suffix), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, suffix := range []string{".sh", ".log", ".rc"} {
		if err := os.WriteFile(filepath.Join(dir, old+"-legacy-done"+suffix), []byte("0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	recentFinished := fmt.Sprintf("CORV_RC_V2 0 %d 172800\n", now.Add(-time.Hour).Unix())
	oldFinished := fmt.Sprintf("CORV_RC_V2 0 %d 1\n", now.Add(-2*jobTTL).Unix())
	for name, rc := range map[string]string{"recent-done": recentFinished, "old-done": oldFinished} {
		for _, suffix := range []string{".sh", ".log", ".rc"} {
			data := "x"
			if suffix == ".rc" {
				data = rc
			}
			if err := os.WriteFile(filepath.Join(dir, old+"-"+name+suffix), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	cmd := exec.Command("sh", "-c", sweepRemoteCommand(now))
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
		if _, err := os.Stat(filepath.Join(dir, old+"-legacy-done"+suffix)); !os.IsNotExist(err) {
			t.Fatalf("completed run %s remains: %v", suffix, err)
		}
		if _, err := os.Stat(filepath.Join(dir, old+"-old-done"+suffix)); !os.IsNotExist(err) {
			t.Fatalf("old completed run %s remains: %v", suffix, err)
		}
		if _, err := os.Stat(filepath.Join(dir, old+"-recent-done"+suffix)); err != nil {
			t.Fatalf("recently completed run %s removed: %v", suffix, err)
		}
	}
}

func TestStartJobCommandWritesTimedExitRecord(t *testing.T) {
	uid, err := exec.Command("id", "-u").Output()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	id := fmt.Sprintf("%016x-test", time.Now().Unix())
	payload := "printf 'done\\n'; exit 7\n"
	cmd := exec.Command("sh", "-c", startJobCommand(id, int64(len(payload))))
	cmd.Env = append(os.Environ(), "TMPDIR="+root)
	cmd.Stdin = strings.NewReader(payload)
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "CORV_STARTED") {
		t.Fatalf("start: %v: %s", err, out)
	}

	dir := filepath.Join(root, "corv-jobs-"+strings.TrimSpace(string(uid)))
	rcPath := filepath.Join(dir, id+".rc")
	deadline := time.Now().Add(5 * time.Second)
	var raw []byte
	for time.Now().Before(deadline) {
		raw, err = os.ReadFile(rcPath)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("read exit record: %v", err)
	}
	exit, err := parseRemoteExit(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if exit.code != 7 || exit.finishedAt.IsZero() || exit.duration < 0 {
		t.Fatalf("exit record = %#v", exit)
	}
	for _, path := range []string{dir, filepath.Join(dir, id+".sh"), filepath.Join(dir, id+".log"), rcPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o600)
		if info.IsDir() {
			want = 0o700
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), want)
		}
	}
}

func TestStartJobCommandRejectsIncompleteUpload(t *testing.T) {
	uid, err := exec.Command("id", "-u").Output()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	id := fmt.Sprintf("%016x-incomplete", time.Now().Unix())
	cmd := exec.Command("sh", "-c", startJobCommand(id, 64))
	cmd.Env = append(os.Environ(), "TMPDIR="+root)
	cmd.Stdin = strings.NewReader("partial")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "CORV_UPLOAD_INCOMPLETE") {
		t.Fatalf("incomplete upload: err=%v output=%q", err, out)
	}
	dir := filepath.Join(root, "corv-jobs-"+strings.TrimSpace(string(uid)))
	for _, suffix := range []string{".upload", ".sh", ".log", ".rc"} {
		if _, err := os.Stat(filepath.Join(dir, id+suffix)); !os.IsNotExist(err) {
			t.Fatalf("partial upload left %s: %v", suffix, err)
		}
	}
}
