//go:build windows

package broker

import (
	"os"
	"path/filepath"

	"github.com/khalid-src/corv-client/internal/paths"
	"golang.org/x/sys/windows"
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
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0,
		1,
		0,
		&overlapped,
	); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlapped)
		_ = f.Close()
	}, nil
}
