//go:build darwin

package vault

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"strings"
)

const macOSVaultService = "corv-vault-key"

func (s *Store) osKey() ([]byte, bool, error) {
	account := "default"
	if u, err := user.Current(); err == nil && u.Username != "" {
		account = u.Username
	}
	out, err := runKeyCommand("/usr/bin/security", "find-generic-password", "-s", macOSVaultService, "-a", account, "-w")
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, false, fmt.Errorf("macOS Keychain did not return the Corv vault key; the item may be missing, locked, or unavailable in this session: %w", err)
		}
		return nil, false, fmt.Errorf("read Corv vault key from macOS Keychain: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(key) != 32 {
		return nil, false, errors.New("macOS Keychain returned an invalid Corv vault key")
	}
	return key, true, nil
}
