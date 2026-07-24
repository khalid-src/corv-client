package statelock

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWithLockSerializesWriters(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	path := filepath.Join(os.Getenv("CORV_HOME"), "counter")
	if err := os.WriteFile(path, []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}

	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	errs := make(chan error, 2)
	var once sync.Once
	write := func() error {
		return WithLock(func() error {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value, err := strconv.Atoi(string(data))
			if err != nil {
				return err
			}
			once.Do(func() {
				close(firstEntered)
				<-releaseFirst
			})
			return os.WriteFile(path, []byte(strconv.Itoa(value+1)), 0o600)
		})
	}

	go func() { errs <- write() }()
	<-firstEntered
	go func() { errs <- write() }()
	time.Sleep(100 * time.Millisecond)
	close(releaseFirst)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "2" {
		t.Fatalf("counter = %q, want 2", data)
	}
}

func TestWithLockReleasesAfterFailure(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	want := errors.New("transaction failed")
	if err := WithLock(func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if err := WithLock(func() error { return nil }); err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
}

func TestWithLockTimesOutClearly(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	originalWait := waitForLock
	originalRetry := retryEvery
	waitForLock = 80 * time.Millisecond
	retryEvery = 10 * time.Millisecond
	t.Cleanup(func() {
		waitForLock = originalWait
		retryEvery = originalRetry
	})

	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- WithLock(func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	err := WithLock(func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "another corv process") {
		t.Fatalf("contention error = %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
