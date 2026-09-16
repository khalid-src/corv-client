//go:build linux

package vault

import (
	"encoding/base64"
	"errors"
	"fmt"
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
func (s *Store) osKey() ([]byte, bool, error) {
	path, err := exec.LookPath("secret-tool")
	if err != nil {
		return nil, false, fmt.Errorf("Secret Service key cannot be read because secret-tool is unavailable: %w", err)
	}
	out, err := runKeyCommand(path, "lookup", "application", "corv", "service", "vault-key")
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, false, fmt.Errorf("Secret Service did not return the Corv vault key; the key may be missing, locked, or unavailable in this session: %w", err)
		}
		return nil, false, fmt.Errorf("read Corv vault key from Secret Service: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(key) != 32 {
		return nil, false, errors.New("Secret Service returned an invalid Corv vault key")
	}
	return key, true, nil
}
