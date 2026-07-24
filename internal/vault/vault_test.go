package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVaultRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := New(filepath.Join(dir, "vault.json"), filepath.Join(dir, "vault.key"))

	if err := store.Set("profile:srv1", Secret{Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Get("profile:srv1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("missing secret")
	}
	if got.Password != "secret" {
		t.Fatalf("password = %q", got.Password)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := New(filepath.Join(dir, "vault.json"), filepath.Join(dir, "vault.key"))

	ciphertext, err := store.Seal([]byte("profile metadata"))
	if err != nil {
		t.Fatal(err)
	}
	if string(ciphertext) == "profile metadata" {
		t.Fatal("Seal returned plaintext")
	}
	plaintext, err := store.Open(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "profile metadata" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestOpenWithDifferentKeyFails(t *testing.T) {
	dir := t.TempDir()
	store := New(filepath.Join(dir, "vault.json"), filepath.Join(dir, "vault.key"))
	ciphertext, err := store.Seal([]byte("profile metadata"))
	if err != nil {
		t.Fatal(err)
	}

	other := New(filepath.Join(dir, "other-vault.json"), filepath.Join(dir, "other.key"))
	if _, err := other.Open(ciphertext); err == nil {
		t.Fatal("expected decrypt failure with different key")
	}
}

func TestResetKeepsKeyBackendForSurvivingConfig(t *testing.T) {
	dir := t.TempDir()
	store := New(filepath.Join(dir, "vault.json"), filepath.Join(dir, "vault.key"))
	if err := store.Set("profile:web", Secret{Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	backendBefore, err := os.ReadFile(store.backendPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Reset(false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("vault file remains: %v", err)
	}
	backendAfter, err := os.ReadFile(store.backendPath)
	if err != nil || !bytes.Equal(backendAfter, backendBefore) {
		t.Fatalf("backend marker changed: before=%q after=%q err=%v", backendBefore, backendAfter, err)
	}
	if _, err := os.Stat(store.keyPath); err != nil {
		t.Fatalf("local key was removed: %v", err)
	}
}

func TestResetWithKeyRemovesLocalVaultFiles(t *testing.T) {
	dir := t.TempDir()
	store := New(filepath.Join(dir, "vault.json"), filepath.Join(dir, "vault.key"))
	if err := store.Set("profile:web", Secret{Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Reset(true); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{store.path, store.backendPath, store.keyPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s remains: %v", path, err)
		}
	}
}

func TestResetReportsRemovalFailure(t *testing.T) {
	dir := t.TempDir()
	store := New(filepath.Join(dir, "vault.json"), filepath.Join(dir, "vault.key"))
	original := removeFile
	removeFile = func(string) error { return errors.New("access denied") }
	t.Cleanup(func() { removeFile = original })

	if err := store.Reset(false); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("reset error = %v", err)
	}
}

func TestLegacyVaultPinsBackendOnNextSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	keyPath := filepath.Join(dir, "vault.key")
	store := New(path, keyPath)
	if err := store.Set("profile:srv1", Secret{Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(store.backendPath); err != nil {
		t.Fatal(err)
	}

	legacy := New(path, keyPath)
	if _, ok, err := legacy.Get("profile:srv1"); err != nil || !ok {
		t.Fatalf("legacy read: ok=%v err=%v", ok, err)
	}
	if _, err := os.Stat(legacy.backendPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backend marker written during read: %v", err)
	}
	if err := legacy.Set("profile:srv2", Secret{Password: "other"}); err != nil {
		t.Fatal(err)
	}
	backend, err := os.ReadFile(legacy.backendPath)
	if err != nil {
		t.Fatal(err)
	}
	if !validBackend(string(backend)) {
		t.Fatalf("backend marker = %q", backend)
	}
}

func TestLegacyVaultSelectsBackendBeforeProfileSeal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	keyPath := filepath.Join(dir, "vault.key")
	store := New(path, keyPath)
	if err := store.Set("profile:srv1", Secret{Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(store.backendPath); err != nil {
		t.Fatal(err)
	}

	legacy := New(path, keyPath)
	ciphertext, err := legacy.Seal([]byte("profile metadata"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := legacy.Get("profile:srv1"); err != nil || !ok {
		t.Fatalf("vault read after profile seal: ok=%v err=%v", ok, err)
	}
	plaintext, err := legacy.Open(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "profile metadata" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestRecordedUnavailableBackendFails(t *testing.T) {
	dir := t.TempDir()
	store := New(filepath.Join(dir, "vault.json"), filepath.Join(dir, "vault.key"))
	if err := store.Set("profile:srv1", Secret{Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	backend := keyBackendOS
	if runtime.GOOS != "windows" {
		backend = keyBackendWindows
	}
	if err := os.WriteFile(store.backendPath, []byte(backend), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened := New(store.path, store.keyPath)
	if _, _, err := reopened.Get("profile:srv1"); err == nil {
		t.Fatal("expected unavailable backend error")
	}
}

func TestVaultSaveFailureKeepsPreviousFile(t *testing.T) {
	dir := t.TempDir()
	store := New(filepath.Join(dir, "vault.json"), filepath.Join(dir, "vault.key"))
	if err := store.Set("profile:srv1", Secret{Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}

	originalWrite := writeFile
	writeFile = func(path string, data []byte, perm os.FileMode) error {
		if path == store.path {
			return errors.New("replace failed")
		}
		return originalWrite(path, data, perm)
	}
	t.Cleanup(func() { writeFile = originalWrite })
	if err := store.Set("profile:srv2", Secret{Password: "other"}); err == nil {
		t.Fatal("expected save failure")
	}
	after, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed save changed the existing vault")
	}
}
