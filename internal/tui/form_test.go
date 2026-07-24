package tui

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/vault"
)

func TestRenamePreservesStoredCredentials(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CORV_HOME", dir)
	secrets := vault.New(filepath.Join(dir, "vault.json"), filepath.Join(dir, "vault.key"))
	store := profile.NewStore(filepath.Join(dir, "config.json"), secrets)
	oldRef := "profile:old-name"
	if err := secrets.Set(oldRef, vault.Secret{Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	reg := profile.Registry{}
	if err := reg.Set(profile.Profile{Name: "old-name", Target: "user@example.com", SecretRef: oldRef}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(reg); err != nil {
		t.Fatal(err)
	}

	m := model{store: store, secrets: secrets}
	m.form = newForm(reg.Profiles["old-name"], "old-name")
	m.form.inputs[fName].SetValue("new-name")
	if err := m.saveForm(); err != nil {
		t.Fatal(err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	renamed, ok := got.Get("new-name")
	if !ok || !strings.HasPrefix(renamed.SecretRef, "profile:new-name:") || renamed.SecretRef == oldRef {
		t.Fatalf("renamed profile = %#v", renamed)
	}
	secret, ok, err := secrets.Get(renamed.SecretRef)
	if err != nil || !ok || secret.Password != "secret" {
		t.Fatalf("renamed secret: ok=%v secret=%#v err=%v", ok, secret, err)
	}
	if _, ok, err := secrets.Get(oldRef); err != nil || ok {
		t.Fatalf("old secret remains: ok=%v err=%v", ok, err)
	}
}

func TestProfileSaveFailurePreservesOriginalCredential(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CORV_HOME", dir)
	secrets := vault.New(filepath.Join(dir, "vault.json"), filepath.Join(dir, "vault.key"))
	store := profile.NewStore(filepath.Join(dir, "config.json"), secrets)
	oldRef := "profile:web"
	if err := secrets.Set(oldRef, vault.Secret{Password: "old-password"}); err != nil {
		t.Fatal(err)
	}
	reg := profile.Registry{}
	if err := reg.Set(profile.Profile{Name: "web", Target: "old@example.com", SecretRef: oldRef}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(reg); err != nil {
		t.Fatal(err)
	}

	originalSave := saveProfileRegistry
	saveProfileRegistry = func(*profile.Store, profile.Registry) error { return errors.New("save failed") }
	t.Cleanup(func() { saveProfileRegistry = originalSave })

	m := model{store: store, secrets: secrets}
	m.form = newForm(reg.Profiles["web"], "web")
	m.form.inputs[fHost].SetValue("new.example.com")
	m.form.inputs[fPassword].SetValue("new-password")
	if err := m.saveForm(); err == nil {
		t.Fatal("expected save failure")
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := loaded.Get("web")
	if !ok || got.Target != "old@example.com" || got.SecretRef != oldRef {
		t.Fatalf("profile after failure = %#v", got)
	}
	secret, ok, err := secrets.Get(oldRef)
	if err != nil || !ok || secret.Password != "old-password" {
		t.Fatalf("original credential after failure: ok=%v secret=%#v err=%v", ok, secret, err)
	}
}

func TestDeleteSelectedSurfacesCredentialDeleteFailure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CORV_HOME", dir)
	secrets := vault.New(filepath.Join(dir, "vault.json"), filepath.Join(dir, "vault.key"))
	store := profile.NewStore(filepath.Join(dir, "config.json"), secrets)
	reg := profile.Registry{}
	if err := reg.Set(profile.Profile{Name: "web", Target: "example.com", SecretRef: "profile:web"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(reg); err != nil {
		t.Fatal(err)
	}

	originalDelete := deleteStoredSecret
	deleteStoredSecret = func(*vault.Store, string) error { return errors.New("vault write failed") }
	t.Cleanup(func() { deleteStoredSecret = originalDelete })

	m := model{store: store, secrets: secrets}
	if _, err := m.deleteSelected("web"); err == nil || !strings.Contains(err.Error(), "stored credentials") {
		t.Fatalf("delete error = %v", err)
	}
}

func TestRenameKeepsDestinationSecretReference(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CORV_HOME", dir)
	secrets := vault.New(filepath.Join(dir, "vault.json"), filepath.Join(dir, "vault.key"))
	store := profile.NewStore(filepath.Join(dir, "config.json"), secrets)
	ref := "profile:new-name"
	if err := secrets.Set(ref, vault.Secret{Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	reg := profile.Registry{}
	if err := reg.Set(profile.Profile{Name: "old-name", Target: "user@example.com", SecretRef: ref}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(reg); err != nil {
		t.Fatal(err)
	}

	m := model{store: store, secrets: secrets}
	m.form = newForm(reg.Profiles["old-name"], "old-name")
	m.form.inputs[fName].SetValue("new-name")
	if err := m.saveForm(); err != nil {
		t.Fatal(err)
	}

	secret, ok, err := secrets.Get(ref)
	if err != nil || !ok || secret.Password != "secret" {
		t.Fatalf("destination secret: ok=%v secret=%#v err=%v", ok, secret, err)
	}
}
