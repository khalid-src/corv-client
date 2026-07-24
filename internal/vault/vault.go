package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/khalid-src/corv-client/internal/atomicfile"
)

type Secret struct {
	Password   string `json:"password,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type Store struct {
	path        string
	keyPath     string
	backendPath string
	backend     string
	mu          sync.Mutex
}

type encryptedVault struct {
	Version int               `json:"version"`
	Items   map[string]string `json:"items"`
}

var (
	writeFile  = atomicfile.Write
	removeFile = os.Remove
)

func New(path, keyPath string) *Store {
	return &Store{path: path, keyPath: keyPath, backendPath: keyPath + ".backend"}
}

// Seal encrypts plaintext with the vault key and returns the same base64
// envelope used for individual vault items.
func (s *Store) Seal(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, backend, err := s.keyForWrite()
	if err != nil {
		return nil, err
	}
	encoded, err := seal(key, plaintext)
	if err != nil {
		return nil, err
	}
	if err := s.persistBackend(backend); err != nil {
		return nil, err
	}
	return []byte(encoded), nil
}

// Open decrypts ciphertext produced by Seal.
func (s *Store) Open(ciphertext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	candidates, err := s.keysForRead()
	if err != nil {
		return nil, err
	}
	var openErr error
	for _, candidate := range candidates {
		plaintext, err := open(candidate.key, string(ciphertext))
		if err == nil {
			s.backend = candidate.backend
			return plaintext, nil
		}
		openErr = err
	}
	if openErr == nil {
		openErr = errors.New("no vault key is available")
	}
	return nil, openErr
}

func (s *Store) Set(ref string, secret Secret) error {
	if ref == "" {
		return errors.New("secret ref is required")
	}
	data, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	return s.setRaw(ref, data)
}

func (s *Store) Get(ref string) (Secret, bool, error) {
	raw, ok, err := s.getRaw(ref)
	if err != nil || !ok {
		return Secret{}, ok, err
	}
	var secret Secret
	if err := json.Unmarshal(raw, &secret); err != nil {
		return Secret{}, false, err
	}
	return secret, true, nil
}

func (s *Store) Delete(ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	v, err := s.load()
	if err != nil {
		return err
	}
	key, backend, err := s.keyForVault(v)
	if err != nil {
		return err
	}
	delete(v.Items, ref)
	return s.save(v, key, backend)
}

// Reset deletes the vault items without reading or decrypting them. When
// includeKey is true it also removes the backend marker and Corv's local key
// file. Externally provisioned OS keychain entries are not modified.
func (s *Store) Reset(includeKey bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	targets := []string{s.path}
	if includeKey {
		targets = append(targets, s.backendPath, s.keyPath)
	}
	var firstErr error
	for _, target := range targets {
		if err := removeFile(target); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	if includeKey {
		s.backend = ""
	}
	return firstErr
}

func (s *Store) setRaw(ref string, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	v, err := s.load()
	if err != nil {
		return err
	}
	key, backend, err := s.keyForVault(v)
	if err != nil {
		return err
	}
	enc, err := seal(key, raw)
	if err != nil {
		return err
	}
	v.Items[ref] = enc
	return s.save(v, key, backend)
}

func (s *Store) getRaw(ref string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	v, err := s.load()
	if err != nil {
		return nil, false, err
	}
	item, ok := v.Items[ref]
	if !ok {
		return nil, false, nil
	}
	candidates, err := s.keysForRead()
	if err != nil {
		return nil, false, err
	}
	var openErr error
	for _, candidate := range candidates {
		raw, err := open(candidate.key, item)
		if err == nil {
			s.backend = candidate.backend
			return raw, true, nil
		}
		openErr = err
	}
	return nil, false, openErr
}

func (s *Store) load() (encryptedVault, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return encryptedVault{Version: 1, Items: map[string]string{}}, nil
	}
	if err != nil {
		return encryptedVault{}, err
	}
	var v encryptedVault
	if err := json.Unmarshal(data, &v); err != nil {
		return encryptedVault{}, fmt.Errorf("read vault: %w", err)
	}
	if v.Items == nil {
		v.Items = map[string]string{}
	}
	if v.Version == 0 {
		v.Version = 1
	}
	return v, nil
}

func (s *Store) save(v encryptedVault, _ []byte, backend string) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := writeFile(s.path, data, 0o600); err != nil {
		return err
	}
	return s.persistBackend(backend)
}

type keyCandidate struct {
	backend string
	key     []byte
}

const (
	keyBackendFile    = "file"
	keyBackendOS      = "os"
	keyBackendWindows = "dpapi"
)

func validBackend(backend string) bool {
	return backend == keyBackendFile || backend == keyBackendOS || backend == keyBackendWindows
}

func (s *Store) keyForWrite() ([]byte, string, error) {
	if s.backend != "" {
		candidate, err := s.keyForBackend(s.backend, false)
		return candidate.key, candidate.backend, err
	}
	if backend, err := s.readBackend(); err != nil {
		return nil, "", err
	} else if backend != "" {
		candidate, err := s.keyForBackend(backend, false)
		if err != nil {
			return nil, "", err
		}
		s.backend = candidate.backend
		return candidate.key, candidate.backend, nil
	}
	if vault, err := s.load(); err != nil {
		return nil, "", err
	} else if len(vault.Items) > 0 {
		return s.keyForVault(vault)
	}
	candidates, err := s.legacyKeyCandidates(true)
	if err != nil {
		return nil, "", err
	}
	if len(candidates) == 0 {
		return nil, "", errors.New("no vault key is available")
	}
	s.backend = candidates[0].backend
	return candidates[0].key, candidates[0].backend, nil
}

func (s *Store) keyForVault(v encryptedVault) ([]byte, string, error) {
	if len(v.Items) == 0 {
		return s.keyForWrite()
	}
	if s.backend != "" {
		candidate, err := s.keyForBackend(s.backend, false)
		return candidate.key, candidate.backend, err
	}
	if backend, err := s.readBackend(); err != nil {
		return nil, "", err
	} else if backend != "" {
		candidate, err := s.keyForBackend(backend, false)
		if err != nil {
			return nil, "", err
		}
		s.backend = candidate.backend
		return candidate.key, candidate.backend, nil
	}
	candidates, err := s.legacyKeyCandidates(false)
	if err != nil {
		return nil, "", err
	}
	var sample string
	for _, item := range v.Items {
		sample = item
		break
	}
	for _, candidate := range candidates {
		if _, err := open(candidate.key, sample); err == nil {
			s.backend = candidate.backend
			return candidate.key, candidate.backend, nil
		}
	}
	return nil, "", errors.New("vault cannot be decrypted with an available key")
}

func (s *Store) keysForRead() ([]keyCandidate, error) {
	if s.backend != "" {
		candidate, err := s.keyForBackend(s.backend, false)
		if err != nil {
			return nil, err
		}
		return []keyCandidate{candidate}, nil
	}
	backend, err := s.readBackend()
	if err != nil {
		return nil, err
	}
	if backend != "" {
		candidate, err := s.keyForBackend(backend, false)
		if err != nil {
			return nil, err
		}
		s.backend = candidate.backend
		return []keyCandidate{candidate}, nil
	}
	return s.legacyKeyCandidates(false)
}

func (s *Store) readBackend() (string, error) {
	data, err := os.ReadFile(s.backendPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read vault key backend: %w", err)
	}
	backend := string(data)
	if !validBackend(backend) {
		return "", fmt.Errorf("invalid vault key backend %q", backend)
	}
	return backend, nil
}

func (s *Store) persistBackend(backend string) error {
	if !validBackend(backend) {
		return fmt.Errorf("invalid vault key backend %q", backend)
	}
	if err := writeFile(s.backendPath, []byte(backend), 0o600); err != nil {
		return fmt.Errorf("write vault key backend: %w", err)
	}
	s.backend = backend
	return nil
}

func seal(key, raw []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := append(nonce, gcm.Seal(nil, nonce, raw, nil)...)
	return base64.StdEncoding.EncodeToString(out), nil
}

func open(key []byte, encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("vault item is truncated")
	}
	nonce := data[:gcm.NonceSize()]
	ct := data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
