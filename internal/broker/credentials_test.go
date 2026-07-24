package broker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/statelock"
	"github.com/khalid-src/corv-client/internal/vault"
)

func TestDialSurfacesVaultReadError(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.json")
	if err := os.WriteFile(vaultPath, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &server{secrets: vault.New(vaultPath, filepath.Join(dir, "vault.key"))}
	p := profile.Profile{Name: "srv1", Target: "example.com", SecretRef: "profile:srv1"}

	_, err := s.dial(p, profile.Registry{})
	if err == nil || !strings.Contains(err.Error(), "stored credentials") || strings.Contains(err.Error(), "authentication") {
		t.Fatalf("error = %v", err)
	}
}

func TestConnectionSnapshotDoesNotMixProfileAndCredentialVersions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CORV_HOME", dir)
	secrets := vault.New(filepath.Join(dir, "vault.json"), filepath.Join(dir, "vault.key"))
	store := profile.NewStore(filepath.Join(dir, "config.json"), secrets)
	if err := secrets.Set("profile:srv1:old", vault.Secret{Password: "old-password"}); err != nil {
		t.Fatal(err)
	}
	reg := profile.Registry{}
	if err := reg.Set(profile.Profile{Name: "srv1", Target: "old.example.com", SecretRef: "profile:srv1:old"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(reg); err != nil {
		t.Fatal(err)
	}

	writerReady := make(chan struct{})
	releaseWriter := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		writerDone <- statelock.WithLock(func() error {
			if err := secrets.Set("profile:srv1:new", vault.Secret{Password: "new-password"}); err != nil {
				return err
			}
			close(writerReady)
			<-releaseWriter
			updated, err := store.Load()
			if err != nil {
				return err
			}
			p, _ := updated.Get("srv1")
			p.Target = "new.example.com"
			p.SecretRef = "profile:srv1:new"
			if err := updated.Set(p); err != nil {
				return err
			}
			return store.Save(updated)
		})
	}()
	<-writerReady

	type result struct {
		snapshot connectionSnapshot
		ok       bool
		err      error
	}
	resultCh := make(chan result, 1)
	s := &server{store: store, secrets: secrets}
	go func() {
		snapshot, ok, err := s.loadConnectionSnapshot("srv1")
		resultCh <- result{snapshot: snapshot, ok: ok, err: err}
	}()
	select {
	case got := <-resultCh:
		t.Fatalf("snapshot bypassed state transaction: %#v", got)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseWriter)
	if err := <-writerDone; err != nil {
		t.Fatal(err)
	}
	got := <-resultCh
	if got.err != nil || !got.ok || got.snapshot.profile.Target != "new.example.com" || got.snapshot.secret.Password != "new-password" {
		t.Fatalf("snapshot = %#v, ok=%v err=%v", got.snapshot, got.ok, got.err)
	}
}

func TestExecClassifiesVaultReadErrorAsLocal(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.json")
	secrets := vault.New(vaultPath, filepath.Join(dir, "vault.key"))
	if err := secrets.Set("profile:srv1", vault.Secret{Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	store := profile.NewStore(filepath.Join(dir, "config.json"), secrets)
	reg := profile.Registry{}
	if err := reg.Set(profile.Profile{Name: "srv1", Target: "example.com", SecretRef: "profile:srv1"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(reg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultPath, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &server{store: store, secrets: secrets}
	resp := s.exec(Request{Name: "srv1", Command: []string{"true"}})
	if resp.OK || resp.Kind != "local_error" || !strings.Contains(resp.Error, "credentials") || strings.Contains(resp.Error, "authentication") {
		t.Fatalf("response = %#v", resp)
	}
}
