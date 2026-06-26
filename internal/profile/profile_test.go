package profile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type testSealer struct {
	key byte
}

func (s testSealer) Seal(plaintext []byte) ([]byte, error) {
	out := append([]byte{s.key}, plaintext...)
	return []byte(base64.StdEncoding.EncodeToString(out)), nil
}

func (s testSealer) Open(ciphertext []byte) ([]byte, error) {
	out, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, err
	}
	if len(out) == 0 || out[0] != s.key {
		return nil, errors.New("wrong key")
	}
	return out[1:], nil
}

func TestStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store := NewStore(path, testSealer{key: 1})

	reg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Set(Profile{Name: "srv1", Target: "user@example.com", Port: 2222, IdentityFile: "key", SecretRef: "profile:srv1"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(reg); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("user@example.com")) {
		t.Fatal("profile config was written in plaintext")
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	p, ok := loaded.Get("srv1")
	if !ok {
		t.Fatal("missing profile")
	}
	if p.Target != "user@example.com" || p.Port != 2222 || p.IdentityFile != "key" || p.SecretRef != "profile:srv1" {
		t.Fatalf("unexpected profile: %#v", p)
	}
}

func TestStoreMigratesLegacyPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	legacy := Registry{Profiles: map[string]Profile{
		"srv1": {Name: "srv1", Target: "user@example.com"},
	}}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	store := NewStore(path, testSealer{key: 2})
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Get("srv1"); !ok {
		t.Fatal("legacy profile missing after load")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		t.Fatal("legacy profile config was not migrated to encrypted form")
	}
}

func TestStoreOpenWithDifferentKeyFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store := NewStore(path, testSealer{key: 3})
	reg := Registry{}
	if err := reg.Set(Profile{Name: "srv1", Target: "user@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(reg); err != nil {
		t.Fatal(err)
	}

	wrongKey := NewStore(path, testSealer{key: 4})
	if _, err := wrongKey.Load(); err == nil {
		t.Fatal("expected decrypt failure with different key")
	}
}

func TestProfileValidation(t *testing.T) {
	tests := []Profile{
		{Name: "", Target: "user@example.com"},
		{Name: "bad name", Target: "user@example.com"},
		{Name: "srv1", Target: ""},
		{Name: "srv1", Target: "user@example.com extra"},
		{Name: "srv1", Target: "user@example.com", Port: 70000},
	}

	for _, tt := range tests {
		reg := Registry{}
		if err := reg.Set(tt); err == nil {
			t.Fatalf("expected validation error for %#v", tt)
		}
	}
}

func TestListSorted(t *testing.T) {
	reg := Registry{}
	for _, p := range []Profile{
		{Name: "b", Target: "b.example.com"},
		{Name: "a", Target: "a.example.com"},
	} {
		if err := reg.Set(p); err != nil {
			t.Fatal(err)
		}
	}

	profiles := reg.List()
	if profiles[0].Name != "a" || profiles[1].Name != "b" {
		t.Fatalf("profiles not sorted: %#v", profiles)
	}
}
