//go:build darwin

package vault

import (
	"encoding/base64"
	"os/exec"
	"os/user"
	"strings"
)

const macOSVaultService = "corv-vault-key"

func (s *Store) osKey() ([]byte, bool) {
	account := "default"
	if u, err := user.Current(); err == nil && u.Username != "" {
		account = u.Username
	}
	out, err := exec.Command("/usr/bin/security", "find-generic-password", "-s", macOSVaultService, "-a", account, "-w").Output()
	if err == nil {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
		if err == nil && len(key) == 32 {
			return key, true
		}
	}
	return nil, false
}
