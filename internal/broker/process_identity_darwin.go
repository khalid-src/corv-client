//go:build darwin

package broker

import "golang.org/x/sys/unix"

func processStartID(pid int) (uint64, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	started := info.Proc.P_starttime
	return uint64(started.Sec)*1_000_000 + uint64(started.Usec), nil
}
