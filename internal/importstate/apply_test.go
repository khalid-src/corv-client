package importstate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/khalid-src/corv-client/internal/paths"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/vault"
)

type failingSealer struct{}

func (failingSealer) Seal([]byte) ([]byte, error)      { return nil, errors.New("save failed") }
func (failingSealer) Open(data []byte) ([]byte, error) { return data, nil }

func TestApplyRollsBackKeysAndSecretsWhenProfileSaveFails(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	p, err := paths.Default()
	if err != nil {
		t.Fatal(err)
	}
	secrets := vault.New(p.VaultFile, p.VaultKey)
	ref := "profile:web"
	oldSecret := vault.Secret{Password: "old password", Passphrase: "old passphrase"}
	if err := secrets.Set(ref, oldSecret); err != nil {
		t.Fatal(err)
	}
	keyPath, err := profile.WriteIdentityFile("web", "old-key")
	if err != nil {
		t.Fatal(err)
	}

	store := profile.NewStore(p.ConfigFile, failingSealer{})
	result, err := Apply(store, secrets, []profile.Imported{{
		Profile:     profile.Profile{Name: "web", Target: "deploy@example.com"},
		Password:    "new password",
		Passphrase:  "new passphrase",
		KeyMaterial: "new-key",
	}})
	if err == nil || result.Added != 1 {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(keyData) != "old-key\n" {
		t.Fatalf("key = %q", keyData)
	}
	got, ok, err := secrets.Get(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got != oldSecret {
		t.Fatalf("secret = %#v, found=%v", got, ok)
	}
	if _, err := os.Stat(p.ConfigFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("config exists after failed save: %v", err)
	}
}

func TestApplyCommitsProfileKeyAndSecretTogether(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	p, err := paths.Default()
	if err != nil {
		t.Fatal(err)
	}
	secrets := vault.New(p.VaultFile, p.VaultKey)
	store := profile.NewStore(p.ConfigFile, secrets)
	result, err := Apply(store, secrets, []profile.Imported{{
		Profile:     profile.Profile{Name: "web", Target: "deploy@example.com"},
		Password:    "  exact password  ",
		KeyMaterial: "private-key-data",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 1 || len(result.Warnings) != 0 {
		t.Fatalf("result = %#v", result)
	}
	reg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reg.Get("web")
	if !ok || got.SecretRef != "profile:web" || got.IdentityFile == "" {
		t.Fatalf("profile = %#v, found=%v", got, ok)
	}
	if filepath.Clean(got.IdentityFile) != filepath.Join(p.Root, "keys", "web.key") {
		t.Fatalf("identity file = %q", got.IdentityFile)
	}
	secret, ok, err := secrets.Get(got.SecretRef)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || secret.Password != "  exact password  " {
		t.Fatalf("secret = %#v, found=%v", secret, ok)
	}
}
