//go:build linux

package vault

import (
	"encoding/base64"
	"os/exec"
	"strings"
)

// osKey reads a provisioned vault key from the Secret Service via secret-tool.
// It deliberately never creates one: auto-provisioning would orphan data that
// is already encrypted with the file key if the keyring is briefly unavailable
// (a lookup failure would otherwise mint a new key). When no usable key is
// present it returns false so the caller falls back to the 0600 file key.
//
// To use the keychain, provision the key once out of band, e.g.:
//
//	secret-tool store --label 'Corv vault key' application corv service vault-key
func (s *Store) osKey() ([]byte, bool) {
	out, err := exec.Command("secret-tool", "lookup", "application", "corv", "service", "vault-key").Output()
	if err != nil {
		return nil, false
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(key) != 32 {
		return nil, false
	}
	return key, true
}
