//go:build windows

package broker

import "syscall"

const (
	createNewProcessGroup = 0x00000200
	detachedProcess       = 0x00000008
	createNoWindow        = 0x08000000
)

// detachSysProcAttr launches the broker detached and windowless so it
// survives the client exiting and never flashes a console.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: createNewProcessGroup | detachedProcess | createNoWindow,
		HideWindow:    true,
	}
}
