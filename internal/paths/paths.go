// Package paths resolves the on-disk locations Corv uses for its local
// state. The root can be overridden with CORV_HOME.
package paths

import (
	"os"
	"path/filepath"
)

// Paths holds the resolved on-disk locations for Corv's state.
type Paths struct {
	Root       string
	ConfigFile string
	AuditFile  string
	VaultFile  string
	VaultKey   string
	RunsDir    string
}

// Default returns the standard Corv paths for the current user. When
// CORV_HOME is set it is used verbatim; otherwise the OS config dir is used
// (e.g. %AppData%\corv, ~/.config/corv).
func Default() (Paths, error) {
	root := os.Getenv("CORV_HOME")
	if root == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return Paths{}, err
		}
		root = filepath.Join(base, "corv")
	}

	return Paths{
		Root:       root,
		ConfigFile: filepath.Join(root, "config.json"),
		AuditFile:  filepath.Join(root, "audit.jsonl"),
		VaultFile:  filepath.Join(root, "vault.json"),
		VaultKey:   filepath.Join(root, "vault.key"),
		RunsDir:    filepath.Join(root, "runs"),
	}, nil
}
