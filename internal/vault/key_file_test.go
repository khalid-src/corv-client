//go:build !windows

package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordedOSBackendPreservesAccessFailure(t *testing.T) {
	dir := t.TempDir()
	store := New(filepath.Join(dir, "vault.json"), filepath.Join(dir, "vault.key"))
	if err := os.WriteFile(store.backendPath, []byte(keyBackendOS), 0o600); err != nil {
		t.Fatal(err)
	}
	original := readOSKey
	readOSKey = func(*Store) ([]byte, bool, error) {
		return nil, false, errors.New("keychain locked")
	}
	t.Cleanup(func() { readOSKey = original })

	_, err := store.Open([]byte("ciphertext"))
	if !errors.Is(err, ErrKeyAccess) {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "keychain locked") {
		t.Fatalf("raw cause was lost: %v", err)
	}
}
