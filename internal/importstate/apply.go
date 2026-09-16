// Package importstate applies imported connections as one local-state transaction.
package importstate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/khalid-src/corv-client/internal/atomicfile"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/statelock"
	"github.com/khalid-src/corv-client/internal/vault"
)

// Result reports the profiles applied and recoverable rows that were skipped.
type Result struct {
	Added    int
	Warnings []string
}

type keyBackup struct {
	path    string
	data    []byte
	perm    fs.FileMode
	existed bool
}

type secretBackup struct {
	ref     string
	secret  vault.Secret
	existed bool
}

// Apply merges imported profiles while holding the shared local-state lock.
func Apply(store *profile.Store, secrets *vault.Store, imported []profile.Imported) (Result, error) {
	var result Result
	err := statelock.WithLock(func() error {
		reg, err := store.Load()
		if err != nil {
			return err
		}
		var keys []keyBackup
		var stored []secretBackup
		rollback := func(cause error) error {
			return errors.Join(cause, rollbackImport(keys, stored, secrets))
		}

		for _, item := range imported {
			p := item.Profile
			if _, exists := reg.Get(p.Name); exists {
				continue
			}
			if err := validateCandidate(p); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("skip %s: %v", p.Name, err))
				continue
			}
			if p.IdentityFile == "" && item.KeyMaterial != "" {
				backup, err := snapshotIdentity(p.Name)
				if err != nil {
					result.Warnings = append(result.Warnings, fmt.Sprintf("skip %s: %v", p.Name, err))
					continue
				}
				keyPath, err := profile.WriteIdentityFile(p.Name, item.KeyMaterial)
				if err != nil {
					result.Warnings = append(result.Warnings, fmt.Sprintf("skip %s: %v", p.Name, err))
					continue
				}
				backup.path = keyPath
				keys = append(keys, backup)
				p.IdentityFile = keyPath
			}
			if item.Password != "" || item.Passphrase != "" {
				ref := "profile:" + p.Name
				old, existed, err := secrets.Get(ref)
				if err != nil {
					return rollback(err)
				}
				if err := secrets.Set(ref, vault.Secret{Password: item.Password, Passphrase: item.Passphrase}); err != nil {
					return rollback(err)
				}
				stored = append(stored, secretBackup{ref: ref, secret: old, existed: existed})
				p.SecretRef = ref
			}
			if err := reg.Set(p); err != nil {
				return rollback(err)
			}
			result.Added++
		}
		if err := store.Save(reg); err != nil {
			return rollback(err)
		}
		return nil
	})
	return result, err
}

func validateCandidate(p profile.Profile) error {
	reg := profile.Registry{}
	return reg.Set(p)
}

func snapshotIdentity(name string) (keyBackup, error) {
	path, err := profile.IdentityFilePath(name)
	if err != nil {
		return keyBackup{}, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return keyBackup{path: path}, nil
	}
	if err != nil {
		return keyBackup{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return keyBackup{}, err
	}
	return keyBackup{path: path, data: data, perm: info.Mode().Perm(), existed: true}, nil
}

func rollbackImport(keys []keyBackup, stored []secretBackup, secrets *vault.Store) error {
	var errs []error
	for i := len(stored) - 1; i >= 0; i-- {
		backup := stored[i]
		var err error
		if backup.existed {
			err = secrets.Set(backup.ref, backup.secret)
		} else {
			err = secrets.Delete(backup.ref)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("restore credential %q: %w", backup.ref, err))
		}
	}
	for i := len(keys) - 1; i >= 0; i-- {
		backup := keys[i]
		var err error
		if backup.existed {
			err = atomicfile.Write(backup.path, backup.data, backup.perm)
		} else {
			err = os.Remove(backup.path)
			if errors.Is(err, os.ErrNotExist) {
				err = nil
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("restore identity file: %w", err))
		}
	}
	return errors.Join(errs...)
}
