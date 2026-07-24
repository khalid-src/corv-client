package cli

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/khalid-src/corv-client/internal/audit"
	"github.com/khalid-src/corv-client/internal/paths"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/vault"
)

func vaultTestDeps(t *testing.T) (deps, paths.Paths) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CORV_HOME", dir)
	p, err := paths.Default()
	if err != nil {
		t.Fatal(err)
	}
	originalStop := stopVaultBroker
	stopVaultBroker = func() error { return nil }
	t.Cleanup(func() { stopVaultBroker = originalStop })
	return depsFromPaths(p), p
}

func depsFromPaths(p paths.Paths) deps {
	secrets := vault.New(p.VaultFile, p.VaultKey)
	return deps{
		store:   profile.NewStore(p.ConfigFile, secrets),
		secrets: secrets,
		log:     audit.NewLog(p.AuditFile),
		paths:   p,
	}
}

func seedProfile(t *testing.T, d deps, name, ref string) {
	t.Helper()
	reg, err := d.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Set(profile.Profile{Name: name, Target: "user@host", SecretRef: ref}); err != nil {
		t.Fatal(err)
	}
	if err := d.store.Save(reg); err != nil {
		t.Fatal(err)
	}
}

func TestVaultResetKeepsConnectionsClearsSecrets(t *testing.T) {
	d, p := vaultTestDeps(t)
	if err := d.secrets.Set("profile:web", vault.Secret{Passphrase: "key-passphrase"}); err != nil {
		t.Fatal(err)
	}
	seedProfile(t, d, "web", "profile:web")
	seedProfile(t, d, "db", "") // a keyless connection must survive untouched

	var out, errOut bytes.Buffer
	if code := vaultReset(d, false, true, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}

	reg, err := d.store.Load()
	if err != nil {
		t.Fatalf("connections unreadable after reset: %v", err)
	}
	web, ok := reg.Get("web")
	if !ok {
		t.Fatal("web connection was lost")
	}
	if web.SecretRef != "" {
		t.Fatalf("secret ref not cleared: %q", web.SecretRef)
	}
	if _, ok := reg.Get("db"); !ok {
		t.Fatal("keyless db connection was lost")
	}
	if _, err := os.Stat(p.VaultFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("vault items file still present: %v", err)
	}
	if _, err := os.Stat(p.VaultKey); err != nil {
		t.Fatalf("working key should be kept, got %v", err)
	}
	if _, _, err := d.secrets.Get("profile:web"); err != nil {
		t.Fatalf("cleared secret should read as absent, got error %v", err)
	}
	if strings.Contains(strings.ToLower(out.String()), "password") || !strings.Contains(out.String(), "stored credentials") {
		t.Fatalf("reset output does not disclose passphrase removal: %q", out.String())
	}
}

func TestVaultResetNoSecretsJustClears(t *testing.T) {
	d, p := vaultTestDeps(t)
	seedProfile(t, d, "web", "")

	var out, errOut bytes.Buffer
	if code := vaultReset(d, false, true, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if _, err := os.Stat(p.VaultFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("vault file should be cleared: %v", err)
	}
	reg, err := d.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Get("web"); !ok {
		t.Fatal("connection lost")
	}
}

func TestVaultResetAbortsOnNo(t *testing.T) {
	d, _ := vaultTestDeps(t)
	if err := d.secrets.Set("profile:web", vault.Secret{Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	seedProfile(t, d, "web", "profile:web")

	var out, errOut bytes.Buffer
	if code := vaultReset(d, false, false, strings.NewReader("n\n"), &out, &errOut); code != 0 {
		t.Fatalf("abort should exit 0, got %d", code)
	}
	reg, _ := d.store.Load()
	web, _ := reg.Get("web")
	if web.SecretRef != "profile:web" {
		t.Fatalf("abort changed the secret ref: %q", web.SecretRef)
	}
	if secret, ok, err := d.secrets.Get("profile:web"); err != nil || !ok || secret.Password != "pw" {
		t.Fatalf("abort dropped the secret: ok=%v err=%v", ok, err)
	}
}

func TestVaultResetWithUnreferencedSecretStillConfirms(t *testing.T) {
	d, _ := vaultTestDeps(t)
	if err := d.secrets.Set("orphan", vault.Secret{Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	seedProfile(t, d, "web", "")

	var out, errOut bytes.Buffer
	if code := vaultReset(d, false, false, strings.NewReader("n\n"), &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if secret, ok, err := d.secrets.Get("orphan"); err != nil || !ok || secret.Password != "pw" {
		t.Fatalf("unconfirmed reset changed orphan secret: ok=%v secret=%#v err=%v", ok, secret, err)
	}
}

func corruptConfig(t *testing.T, d deps, p paths.Paths) {
	t.Helper()
	if err := d.secrets.Set("profile:web", vault.Secret{Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	seedProfile(t, d, "web", "profile:web")
	if err := os.WriteFile(p.ConfigFile, []byte("corrupted-sealed-blob-not-decryptable"), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := depsFromPaths(p).store.Load()
	if err == nil {
		t.Fatalf("expected a locked config, load returned %d profiles", len(reg.Profiles))
	}
	if !errors.Is(err, profile.ErrConfigUnreadable) {
		t.Fatalf("expected ErrConfigUnreadable, got %v", err)
	}
}

func TestVaultResetLockedRefusesWithoutAll(t *testing.T) {
	d, p := vaultTestDeps(t)
	corruptConfig(t, d, p)

	fresh := depsFromPaths(p)
	var out, errOut bytes.Buffer
	if code := vaultReset(fresh, false, true, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if !strings.Contains(errOut.String(), "reset --all") {
		t.Fatalf("missing --all guidance: %s", errOut.String())
	}
	if strings.Contains(errOut.String(), "key is unreadable") || !strings.Contains(errOut.String(), "config file may be damaged") {
		t.Fatalf("reset made an unsupported key diagnosis: %s", errOut.String())
	}
	if _, err := os.Stat(p.ConfigFile); err != nil {
		t.Fatalf("config must not be touched without --all: %v", err)
	}
	if _, err := os.Stat(p.VaultFile); err != nil {
		t.Fatalf("vault must not be touched without --all: %v", err)
	}
}

func TestVaultResetLockedWipesWithAll(t *testing.T) {
	d, p := vaultTestDeps(t)
	corruptConfig(t, d, p)

	fresh := depsFromPaths(p)
	var out, errOut bytes.Buffer
	if code := vaultReset(fresh, true, true, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	for _, path := range []string{p.ConfigFile, p.VaultFile, p.VaultKey} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s should be erased: %v", path, err)
		}
	}
	if !strings.Contains(out.String(), "OS keychain entries were not modified") {
		t.Fatalf("full reset omitted external-key disclosure: %q", out.String())
	}
}

func TestVaultResetFailureRestoresSecretReferences(t *testing.T) {
	d, _ := vaultTestDeps(t)
	if err := d.secrets.Set("profile:web", vault.Secret{Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	seedProfile(t, d, "web", "profile:web")
	originalReset := resetVault
	resetVault = func(*vault.Store, bool) error { return errors.New("access denied") }
	t.Cleanup(func() { resetVault = originalReset })

	var out, errOut bytes.Buffer
	if code := vaultReset(d, false, true, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
	reg, err := d.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	web, _ := reg.Get("web")
	if web.SecretRef != "profile:web" {
		t.Fatalf("secret reference was not restored: %#v", web)
	}
}

func TestVaultResetStopsBeforeChangingState(t *testing.T) {
	d, _ := vaultTestDeps(t)
	if err := d.secrets.Set("profile:web", vault.Secret{Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	seedProfile(t, d, "web", "profile:web")
	stopVaultBroker = func() error { return errors.New("broker busy") }

	var out, errOut bytes.Buffer
	if code := vaultReset(d, false, true, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
	reg, err := d.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	web, _ := reg.Get("web")
	if web.SecretRef != "profile:web" {
		t.Fatalf("broker failure changed profile: %#v", web)
	}
}
