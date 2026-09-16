//go:build !windows && !linux && !darwin

package broker

import "errors"

func processStartID(int) (uint64, error) {
	return 0, errors.New("process identity is unavailable")
}
