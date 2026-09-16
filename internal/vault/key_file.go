//go:build !windows

package vault

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/khalid-src/corv-client/internal/atomicfile"
)

var readOSKey = func(s *Store) ([]byte, bool, error) { return s.osKey() }

func (s *Store) legacyKeyCandidates(create bool) ([]keyCandidate, error) {
	var candidates []keyCandidate
	if key, ok, _ := readOSKey(s); ok {
		candidates = append(candidates, keyCandidate{backend: keyBackendOS, key: key})
	}
	key, err := s.fileKey(false)
	if err == nil {
		candidates = append(candidates, keyCandidate{backend: keyBackendFile, key: key})
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(candidates) == 0 && create {
		key, err := s.fileKey(true)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, keyCandidate{backend: keyBackendFile, key: key})
	}
	return candidates, nil
}

func (s *Store) keyForBackend(backend string, create bool) (keyCandidate, error) {
	switch backend {
	case keyBackendOS:
		key, ok, err := readOSKey(s)
		if err != nil {
			return keyCandidate{}, fmt.Errorf("%w: %w", ErrKeyAccess, err)
		}
		if ok {
			return keyCandidate{backend: backend, key: key}, nil
		}
		return keyCandidate{}, fmt.Errorf("%w: vault uses the OS keychain, but its key is unavailable", ErrKeyAccess)
	case keyBackendFile:
		key, err := s.fileKey(create)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return keyCandidate{}, errors.New("vault uses the file key, but the key file is missing")
			}
			return keyCandidate{}, err
		}
		return keyCandidate{backend: backend, key: key}, nil
	default:
		return keyCandidate{}, fmt.Errorf("vault key backend %q is not supported on this OS", backend)
	}
}

func (s *Store) fileKey(create bool) ([]byte, error) {
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
	if !create {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(s.keyPath), 0o700); err != nil {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := atomicfile.Write(s.keyPath, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}
