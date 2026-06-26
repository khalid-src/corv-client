package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestImportCSVMixedTypes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conns.csv")
	// Columns intentionally out of order, with aliases and a blank row.
	content := `name,host,user,port,key,password,proxy_jump
web1,10.0.0.1,deploy,22,~/.ssh/web1.pem,,
db-prod,db.internal,postgres,5432,,s3cr3t,
,bastion.corp,ops,2200,,,
,,,,,,
behind,10.0.0.9,app,,,hunter2,ops@bastion.corp
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ImportCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 { // blank row skipped
		t.Fatalf("expected 4 imports, got %d", len(got))
	}

	by := map[string]Imported{}
	for _, im := range got {
		by[im.Profile.Name] = im
	}

	// key-based
	if p := by["web1"].Profile; p.Target != "deploy@10.0.0.1" || p.Port != 22 || p.IdentityFile == "" {
		t.Fatalf("web1 = %#v", p)
	}
	if by["web1"].Password != "" {
		t.Fatal("web1 should have no password")
	}
	// password-based
	if by["db-prod"].Password != "s3cr3t" || by["db-prod"].Profile.Port != 5432 {
		t.Fatalf("db-prod = %#v", by["db-prod"])
	}
	// agent/default (no name -> derived from host, no key/pass)
	if _, ok := by["bastion.corp"]; !ok {
		t.Fatal("bastion.corp (name derived from host) missing")
	}
	// bastion + password
	if b := by["behind"]; b.Password != "hunter2" || b.Profile.ProxyJump != "ops@bastion.corp" {
		t.Fatalf("behind = %#v", b)
	}
}

// TestImportCSVSkipsBrokenRows ensures one malformed row (here, an invalid
// port) does not abort the whole import: the valid rows still come through.
func TestImportCSVSkipsBrokenRows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.csv")
	content := `Name,HostName,User,Port,Password
prod-web,1.2.3.4,root,22,
dev-db,192.168.55.12,admin,2222,S3cr3tP@ss!
broken-entry,999.999.999.99,null,-1,
test-node,10.10.10.15,tester,2222,Test1ng!23
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ImportCSV(path)
	if err != nil {
		t.Fatalf("import should not fail on a single broken row: %v", err)
	}
	if len(got) != 3 { // broken-entry (port -1) skipped
		t.Fatalf("expected 3 imports, got %d: %#v", len(got), got)
	}
	for _, im := range got {
		if im.Profile.Name == "broken-entry" {
			t.Fatal("broken-entry should have been skipped")
		}
	}
}

// TestImportCSVInlineKey covers a CSV that declares key auth with an inline
// key (KeyType + KeyString) rather than a file path: the row carries key
// material (prefixed with its type) so the import can materialise it, and no
// IdentityFile path is set yet.
func TestImportCSVInlineKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.csv")
	content := `Name,HostName,User,KeyType,KeyString
inline,1.1.1.1,root,ssh-ed25519,AAAAC3NzaC1lZDI1NTE5AAAExample
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ImportCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].KeyMaterial != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAExample" || got[0].Profile.IdentityFile != "" {
		t.Fatalf("inline key = %#v", got[0])
	}
}

// TestImportCSVKeyPath covers an explicit key-file column mapping straight to
// IdentityFile (no inline material).
func TestImportCSVKeyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.csv")
	if err := os.WriteFile(path, []byte("name,host,identity_file\nkf,4.4.4.4,/etc/ssh/id_ed25519\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ImportCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Profile.IdentityFile != "/etc/ssh/id_ed25519" || got[0].KeyMaterial != "" {
		t.Fatalf("path key = %#v", got[0])
	}
}

func TestImportCSVRequiresHostColumn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.csv")
	if err := os.WriteFile(path, []byte("name,user\nfoo,bar\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportCSV(path); err == nil {
		t.Fatal("expected error when host column is missing")
	}
}

func TestImportDispatchByExtension(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "x.csv")
	if err := os.WriteFile(csvPath, []byte("host\nexample.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Import(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Profile.Target != "example.com" {
		t.Fatalf("csv dispatch = %#v", got)
	}
}
