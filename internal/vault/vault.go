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
)

type Secret struct {
	Password   string `json:"password,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type Store struct {
	path    string
	keyPath string
	mu      sync.Mutex
}

type encryptedVault struct {
	Version int               `json:"version"`
	Items   map[string]string `json:"items"`
}

func New(path, keyPath string) *Store {
	return &Store{path: path, keyPath: keyPath}
}

// Seal encrypts plaintext with the vault key and returns the same base64
// envelope used for individual vault items.
func (s *Store) Seal(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, err := s.key()
	if err != nil {
		return nil, err
	}
	encoded, err := seal(key, plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(encoded), nil
}

// Open decrypts ciphertext produced by Seal.
func (s *Store) Open(ciphertext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, err := s.key()
	if err != nil {
		return nil, err
	}
	return open(key, string(ciphertext))
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

	key, err := s.key()
	if err != nil {
		return err
	}
	v, err := s.load()
	if err != nil {
		return err
	}
	delete(v.Items, ref)
	return s.save(v, key)
}

func (s *Store) setRaw(ref string, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, err := s.key()
	if err != nil {
		return err
	}
	v, err := s.load()
	if err != nil {
		return err
	}
	enc, err := seal(key, raw)
	if err != nil {
		return err
	}
	v.Items[ref] = enc
	return s.save(v, key)
}

func (s *Store) getRaw(ref string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, err := s.key()
	if err != nil {
		return nil, false, err
	}
	v, err := s.load()
	if err != nil {
		return nil, false, err
	}
	item, ok := v.Items[ref]
	if !ok {
		return nil, false, nil
	}
	raw, err := open(key, item)
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
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

func (s *Store) save(v encryptedVault, _ []byte) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(s.path, data, 0o600)
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
