package vault

import (
	"path/filepath"
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
