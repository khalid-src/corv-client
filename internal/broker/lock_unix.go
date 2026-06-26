//go:build !windows

package broker

import (
	"os"
	"path/filepath"

	"github.com/khalid-src/corv-client/internal/paths"
	"golang.org/x/sys/unix"
)

func acquireBrokerLock() (func(), error) {
	p, err := paths.Default()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(p.Root, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(p.Root, "broker.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
