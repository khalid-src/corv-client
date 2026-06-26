//go:build !windows

package vault

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
)

func (s *Store) key() ([]byte, error) {
	if key, ok := s.osKey(); ok {
		return key, nil
	}
	return s.fileKey()
}

func (s *Store) fileKey() ([]byte, error) {
	key, err := os.ReadFile(s.keyPath)
	if err == nil {
		if len(key) != 32 {
			return nil, errors.New("invalid vault key length")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(s.keyPath), 0o700); err != nil {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(s.keyPath, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}
