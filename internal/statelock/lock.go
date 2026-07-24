// Package statelock serializes mutations to Corv's connection and vault state.
package statelock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/khalid-src/corv-client/internal/paths"
)

var (
	errLockBusy = errors.New("state lock is busy")
	waitForLock = 2 * time.Second
	retryEvery  = 25 * time.Millisecond
)

// WithLock runs fn while holding the process-shared local-state lock.
func WithLock(fn func() error) error {
	p, err := paths.Default()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(p.Root, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(p.Root, "state.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	deadline := time.Now().Add(waitForLock)
	var release func()
	for {
		release, err = tryLock(f)
		if err == nil {
			break
		}
		if !errors.Is(err, errLockBusy) {
			return fmt.Errorf("lock saved connections: %w", err)
		}
		if !time.Now().Before(deadline) {
			return errors.New("another corv process is modifying saved connections; try again")
		}
		time.Sleep(retryEvery)
	}
	defer release()
	return fn()
}
