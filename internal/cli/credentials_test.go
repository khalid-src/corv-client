package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/vault"
)

func TestVaultSecretSurfacesReadError(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.json")
	if err := os.WriteFile(vaultPath, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := deps{secrets: vault.New(vaultPath, filepath.Join(dir, "vault.key"))}

	_, err := vaultSecret(d, profile.Profile{Name: "srv1", SecretRef: "profile:srv1"})
	if err == nil || !strings.Contains(err.Error(), "stored credentials") || strings.Contains(err.Error(), "authentication") {
		t.Fatalf("error = %v", err)
	}
	if _, _, err := d.jumpSecret("profile:bastion"); err == nil || !strings.Contains(err.Error(), "jump credentials") {
		t.Fatalf("jump error = %v", err)
	}
}
