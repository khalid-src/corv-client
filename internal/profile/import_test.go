package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrimPath(t *testing.T) {
	cases := map[string]string{
		`  C:\a\b.csv  `:   `C:\a\b.csv`,
		`"C:\a\b.csv"`:     `C:\a\b.csv`,
		`'/home/u/x.csv'`:  `/home/u/x.csv`,
		`"  spaced.csv  "`: `  spaced.csv  `, // inner spaces kept; only quotes stripped
		`plain.csv`:        `plain.csv`,
		`"mismatched.csv'`: `"mismatched.csv'`, // not a matching pair: left as-is
	}
	for in, want := range cases {
		if got := TrimPath(in); got != want {
			t.Errorf("TrimPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteIdentityFile(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	path, err := WriteIdentityFile("web-1", "ssh-ed25519 AAAAExample")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("key file not written: %v", err)
	}
	if string(data) != "ssh-ed25519 AAAAExample\n" {
		t.Fatalf("key file content = %q", data)
	}
}

func TestImportSSHConfigProxyJumpAndInclude(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(confDir, 0o700); err != nil {
		t.Fatal(err)
	}

	main := filepath.Join(dir, "config")
	included := filepath.Join(confDir, "db.conf")
	if err := os.WriteFile(main, []byte(`
Include conf.d/*
Include missing/*

Host app
  HostName 10.0.0.10
  User ubuntu
  Port 2222
  IdentityFile keys/app
  ProxyJump jump1,jump2

Host jump1
  HostName jump1.internal
  User jumpuser
  Port 2022

Host jump2
  HostName 2001:db8::2
  User jumpv6

Host web1
  HostName 10.0.0.1
  User deploy
  Port 2222
  IdentityFile ~/.ssh/web1.pem

Host db1 db1-alt
  HostName db.internal
  User postgres

Host direct
  HostName direct.internal
  ProxyJump none

Host *
  ServerAliveInterval 30
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(included, []byte(`
Host db
  HostName db.internal
  User postgres
  ProxyJump bastion

Host bastion
  HostName bastion.internal
  User ops
  Port 2200
`), 0o600); err != nil {
		t.Fatal(err)
	}

	profiles, err := ImportSSHConfig(main)
	if err != nil {
		t.Fatalf("ImportSSHConfig: %v", err)
	}
	got := map[string]Profile{}
	for _, p := range profiles {
		got[p.Name] = p
	}

	app := got["app"]
	if app.Target != "ubuntu@10.0.0.10" || app.Port != 2222 || app.IdentityFile != "keys/app" || app.ProxyJump != "jumpuser@jump1.internal:2022,jumpv6@[2001:db8::2]" {
		t.Fatalf("app profile = %#v", app)
	}
	db := got["db"]
	if db.Target != "postgres@db.internal" || db.ProxyJump != "ops@bastion.internal:2200" {
		t.Fatalf("db profile = %#v", db)
	}

	web1 := got["web1"]
	if web1.Target != "deploy@10.0.0.1" || web1.Port != 2222 {
		t.Fatalf("web1 profile = %#v", web1)
	}
	if _, ok := got["db1"]; !ok {
		t.Fatal("db1 missing")
	}
	if _, ok := got["db1-alt"]; !ok {
		t.Fatal("db1-alt alias missing")
	}
	if direct := got["direct"]; direct.ProxyJump != "" {
		t.Fatalf("direct ProxyJump = %q, want empty", direct.ProxyJump)
	}
	if _, ok := got["*"]; ok {
		t.Fatal("wildcard host should be skipped")
	}
}
