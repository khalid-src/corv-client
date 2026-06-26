//go:build !windows

package broker

import "syscall"

// detachSysProcAttr puts the broker in its own session so it survives the
// client process exiting.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
