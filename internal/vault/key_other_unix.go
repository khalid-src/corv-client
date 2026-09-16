//go:build !windows && !darwin && !linux

package vault

func (s *Store) osKey() ([]byte, bool, error) {
	return nil, false, nil
}
