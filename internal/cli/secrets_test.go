package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/vault"
)

type failingProfileSealer struct {
	store *vault.Store
	fail  bool
}

func (s *failingProfileSealer) Seal(data []byte) ([]byte, error) {
	if s.fail {
		return nil, errors.New("profile write failed")
	}
	return s.store.Seal(data)
}

func (s *failingProfileSealer) Open(data []byte) ([]byte, error) {
	return s.store.Open(data)
}

func TestAddPreservesExactPasswordBytes(t *testing.T) {
	d, _ := vaultTestDeps(t)
	var stdout, stderr bytes.Buffer
	password := "  pa ss  "
	code := cmdAdd(d, []string{"web", "user@example.com"}, strings.NewReader(password+"\r\n"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	reg, err := d.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	p, ok := reg.Get("web")
	if !ok || p.SecretRef == "" {
		t.Fatalf("profile = %#v, present=%v", p, ok)
	}
	secret, ok, err := d.secrets.Get(p.SecretRef)
	if err != nil || !ok {
		t.Fatalf("read secret: ok=%v err=%v", ok, err)
	}
	if secret.Password != password {
		t.Fatalf("password = %q, want %q", secret.Password, password)
	}
}

func TestAddReplacementPreservesExistingSecretWhenInputIsBlank(t *testing.T) {
	d, _ := vaultTestDeps(t)
	ref := "profile:web"
	password := "  existing password  "
	if err := d.secrets.Set(ref, vault.Secret{Password: password}); err != nil {
		t.Fatal(err)
	}
	seedProfile(t, d, "web", ref)

	var stdout, stderr bytes.Buffer
	code := cmdAdd(d, []string{"web", "new-user@new.example.com"}, strings.NewReader("\n"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	reg, err := d.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	p, ok := reg.Get("web")
	if !ok || p.Target != "new-user@new.example.com" || p.SecretRef != ref {
		t.Fatalf("replacement profile = %#v, present=%v", p, ok)
	}
	secret, ok, err := d.secrets.Get(ref)
	if err != nil || !ok || secret.Password != password {
		t.Fatalf("replacement secret = %#v, present=%v, err=%v", secret, ok, err)
	}
	if !strings.Contains(stdout.String(), "replaced web") {
		t.Fatalf("output = %q", stdout.String())
	}
}

func TestAddReplacementRemovesSupersededSecretReference(t *testing.T) {
	d, _ := vaultTestDeps(t)
	oldRef := "import:legacy-web"
	if err := d.secrets.Set(oldRef, vault.Secret{Password: "old"}); err != nil {
		t.Fatal(err)
	}
	seedProfile(t, d, "web", oldRef)

	var stdout, stderr bytes.Buffer
	password := "  replacement  "
	code := cmdAdd(d, []string{"web", "user@example.com"}, strings.NewReader(password+"\n"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if _, ok, err := d.secrets.Get(oldRef); err != nil || ok {
		t.Fatalf("old secret remains: present=%v err=%v", ok, err)
	}
	reg, err := d.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	p, ok := reg.Get("web")
	if !ok || p.SecretRef == "" || p.SecretRef == oldRef {
		t.Fatalf("replacement profile = %#v, present=%v", p, ok)
	}
	secret, ok, err := d.secrets.Get(p.SecretRef)
	if err != nil || !ok || secret.Password != password {
		t.Fatalf("new secret = %#v, present=%v, err=%v", secret, ok, err)
	}
}

func TestAddReplacementSaveFailurePreservesOriginalPair(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CORV_HOME", dir)
	secrets := vault.New(filepath.Join(dir, "vault.json"), filepath.Join(dir, "vault.key"))
	sealer := &failingProfileSealer{store: secrets}
	d := deps{
		store:   profile.NewStore(filepath.Join(dir, "config.json"), sealer),
		secrets: secrets,
	}
	oldRef := "profile:web:old"
	if err := secrets.Set(oldRef, vault.Secret{Password: "old-password"}); err != nil {
		t.Fatal(err)
	}
	seedProfile(t, d, "web", oldRef)
	sealer.fail = true

	var stdout, stderr bytes.Buffer
	code := cmdAdd(d, []string{"web", "new@example.com"}, strings.NewReader("new-password\n"), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	sealer.fail = false
	reg, err := d.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	p, ok := reg.Get("web")
	if !ok || p.Target != "user@host" || p.SecretRef != oldRef {
		t.Fatalf("profile = %#v, present=%v", p, ok)
	}
	secret, ok, err := secrets.Get(oldRef)
	if err != nil || !ok || secret.Password != "old-password" {
		t.Fatalf("secret = %#v, present=%v, err=%v", secret, ok, err)
	}
}

func TestRemoveReportsCredentialDeletionFailure(t *testing.T) {
	d, p := vaultTestDeps(t)
	ref := "profile:web"
	if err := d.secrets.Set(ref, vault.Secret{Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	seedProfile(t, d, "web", ref)
	if err := os.WriteFile(p.VaultFile, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := cmdRemove(d, []string{"web"}, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "remove stored credentials") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	reg, err := d.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Get("web"); ok {
		t.Fatal("profile was not removed")
	}
}
