package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVerifyChecksum(t *testing.T) {
	data := []byte("corv binary bytes")
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	asset := "corv-linux-amd64"
	// sha256sum -b format: "<hash> *<name>", plus an unrelated line.
	sums := []byte(fmt.Sprintf("deadbeef *corv-darwin-arm64\n%s *%s\n", hash, asset))

	if err := verifyChecksum(data, sums, asset); err != nil {
		t.Fatalf("valid checksum rejected: %v", err)
	}
	if err := verifyChecksum([]byte("tampered"), sums, asset); err == nil {
		t.Fatal("mismatched checksum accepted")
	}
	if err := verifyChecksum(data, sums, "corv-windows-amd64.exe"); err == nil {
		t.Fatal("missing asset accepted")
	}
}

func TestParseTagFromLocation(t *testing.T) {
	got, err := parseTagFromLocation("https://github.com/o/r/releases/tag/v1.2.3")
	if err != nil || got != "v1.2.3" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := parseTagFromLocation("https://github.com/o/r/releases"); err == nil {
		t.Fatal("expected error when no release tag in URL")
	}
}

func TestAssetNameMatchesPlatform(t *testing.T) {
	want := "corv-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	if got := assetName(); got != want {
		t.Fatalf("assetName() = %q, want %q", got, want)
	}
}

func TestReplaceFileSwapsContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corv")
	if err := os.WriteFile(path, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(path, []byte("NEW")); err != nil {
		t.Fatalf("replaceFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "NEW" {
		t.Fatalf("content = %q, want NEW", got)
	}
}
