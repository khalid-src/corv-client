//go:build linux

package broker

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func processStartID(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return 0, fmt.Errorf("read process %d start time: invalid stat", pid)
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) <= 19 {
		return 0, fmt.Errorf("read process %d start time: incomplete stat", pid)
	}
	return strconv.ParseUint(fields[19], 10, 64)
}
