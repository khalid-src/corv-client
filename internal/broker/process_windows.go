//go:build windows

package broker

import "golang.org/x/sys/windows"

func processExited(pid int) (bool, error) {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		if err == windows.ERROR_INVALID_PARAMETER {
			return true, nil
		}
		return false, err
	}
	defer windows.CloseHandle(handle)
	status, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		return false, err
	}
	return status == windows.WAIT_OBJECT_0, nil
}
