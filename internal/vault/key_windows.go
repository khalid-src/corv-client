//go:build windows

package vault

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/khalid-src/corv-client/internal/atomicfile"
)

func (s *Store) legacyKeyCandidates(create bool) ([]keyCandidate, error) {
	candidate, err := s.keyForBackend(keyBackendWindows, create)
	if err != nil {
		if !create && errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return []keyCandidate{candidate}, nil
}

func (s *Store) keyForBackend(backend string, create bool) (keyCandidate, error) {
	if backend != keyBackendWindows {
		return keyCandidate{}, errors.New("vault key backend is not supported on Windows")
	}
	key, err := s.dpapiKey(create)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return keyCandidate{}, errors.New("vault uses the DPAPI key, but the key file is missing")
		}
		return keyCandidate{}, err
	}
	return keyCandidate{backend: backend, key: key}, nil
}

func (s *Store) dpapiKey(create bool) ([]byte, error) {
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
	if !create {
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
	if err := atomicfile.Write(s.keyPath, protected, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}
