//go:build !windows && !darwin && !linux

package vault

func (s *Store) osKey() ([]byte, bool) {
	return nil, false
}
