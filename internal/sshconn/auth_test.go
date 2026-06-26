package sshconn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestAuthMethodsLoadsEncryptedIdentityWithPassphrase(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(key, "test", []byte("passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_rsa")
	if err := os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		t.Fatal(err)
	}

	methods, closers, err := authMethods(path, "passphrase", "")
	closeAuthClosers(closers)
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) == 0 {
		t.Fatal("expected at least one auth method")
	}
}
