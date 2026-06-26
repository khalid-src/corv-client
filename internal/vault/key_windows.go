//go:build windows

package vault

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
)

func (s *Store) key() ([]byte, error) {
	protected, err := os.ReadFile(s.keyPath)
	if err == nil {
		key, err := unprotect(protected)
		if err != nil {
			return nil, err
		}
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
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	protected, err = protect(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(s.keyPath, protected, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}
