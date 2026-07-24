//go:build !windows

package vault_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/vault"
)

func TestReadsV101FileKeyStateWithoutMutation(t *testing.T) {
	fixtureDir := filepath.Join("testdata", "v1.0.1-file")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	vaultPath := filepath.Join(dir, "vault.json")
	keyPath := filepath.Join(dir, "vault.key")

	configBefore := copyFixture(t, filepath.Join(fixtureDir, "config.json"), configPath)
	vaultBefore := copyFixture(t, filepath.Join(fixtureDir, "vault.json"), vaultPath)
	keyHex, err := os.ReadFile(filepath.Join(fixtureDir, "vault.key.hex"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(string(bytes.TrimSpace(keyHex)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}

	secrets := vault.New(vaultPath, keyPath)
	reg, err := profile.NewStore(configPath, secrets).Load()
	if err != nil {
		t.Fatal(err)
	}
	p, ok := reg.Get("legacy")
	if !ok || p.Target != "fixture@example.invalid" || p.Port != 2222 || p.SecretRef != "profile:legacy" {
		t.Fatalf("legacy profile = %#v, present=%v", p, ok)
	}
	secret, ok, err := secrets.Get(p.SecretRef)
	if err != nil || !ok || secret.Password != "legacy password" {
		t.Fatalf("legacy secret = %#v, present=%v, err=%v", secret, ok, err)
	}

	assertFileBytes(t, configPath, configBefore)
	assertFileBytes(t, vaultPath, vaultBefore)
	assertFileBytes(t, keyPath, key)
	if _, err := os.Stat(keyPath + ".backend"); !os.IsNotExist(err) {
		t.Fatalf("read created a backend marker: %v", err)
	}
}

func copyFixture(t *testing.T, source, destination string) []byte {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s changed during read", filepath.Base(path))
	}
}
