package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	"github.com/khalid-src/corv-client/internal/broker"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/statelock"
	"github.com/khalid-src/corv-client/internal/vault"
)

var (
	resetVault      = func(store *vault.Store, includeKey bool) error { return store.Reset(includeKey) }
	stopVaultBroker = func() error {
		self, err := executablePath()
		if err != nil {
			return err
		}
		return broker.NewClient(self).Shutdown()
	}
)

func cmdVault(d deps, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "reset" {
		return fail(stderr, errors.New("usage: corv vault reset [--all] [--yes]"))
	}
	all := false
	assumeYes := false
	for _, arg := range args[1:] {
		switch arg {
		case "--all":
			all = true
		case "--yes", "-y":
			assumeYes = true
		default:
			return fail(stderr, errors.New("usage: corv vault reset [--all] [--yes]"))
		}
	}
	return vaultReset(d, all, assumeYes, stdin, stdout, stderr)
}

func vaultReset(d deps, all, assumeYes bool, stdin io.Reader, stdout, stderr io.Writer) int {
	reg, err := d.store.Load()
	configUnreadable := errors.Is(err, profile.ErrConfigUnreadable)
	if err != nil && !configUnreadable {
		return fail(stderr, fmt.Errorf("read connections: %w", err))
	}

	if configUnreadable {
		if !all {
			fmt.Fprintln(stderr, "corv: saved connections cannot be decrypted. The encryption key may be")
			fmt.Fprintln(stderr, "      unavailable or incorrect, or the config file may be damaged.")
			fmt.Fprintln(stderr, "      Corv cannot safely preserve the connections during a vault reset.")
			fmt.Fprintln(stderr, "      To discard the local connections and vault files, run:")
			fmt.Fprintln(stderr, "        corv vault reset --all")
			return 1
		}
		if !assumeYes && !confirmReset(stdin, stdout,
			"Remove ALL locally saved connections and stored credentials? This cannot be undone [y/N]: ") {
			fmt.Fprintln(stdout, "Aborted; nothing was changed.")
			return 0
		}
		if err := stopVaultBroker(); err != nil {
			return fail(stderr, fmt.Errorf("stop broker before reset: %w", err))
		}
		err := withUnchangedRegistry(d, reg, true, func(profile.Registry) error {
			return fullWipe(d)
		})
		if err != nil {
			return fail(stderr, err)
		}
		printFullWipe(stdout)
		return 0
	}

	withSecrets := profilesWithSecrets(reg)

	if all {
		if !assumeYes && !confirmReset(stdin, stdout, fmt.Sprintf(
			"Remove ALL locally saved connections (%d) and stored credentials? This cannot be undone [y/N]: ",
			len(reg.Profiles))) {
			fmt.Fprintln(stdout, "Aborted; nothing was changed.")
			return 0
		}
		if err := stopVaultBroker(); err != nil {
			return fail(stderr, fmt.Errorf("stop broker before reset: %w", err))
		}
		err := withUnchangedRegistry(d, reg, false, func(profile.Registry) error {
			return fullWipe(d)
		})
		if err != nil {
			return fail(stderr, err)
		}
		printFullWipe(stdout)
		return 0
	}

	if len(withSecrets) == 0 {
		if !assumeYes && !confirmReset(stdin, stdout,
			"Clear all stored credentials from the local vault? Saved connections will remain [y/N]: ") {
			fmt.Fprintln(stdout, "Aborted; nothing was changed.")
			return 0
		}
		if err := stopVaultBroker(); err != nil {
			return fail(stderr, fmt.Errorf("stop broker before reset: %w", err))
		}
		err := withUnchangedRegistry(d, reg, false, func(profile.Registry) error {
			return resetVault(d.secrets, false)
		})
		if err != nil {
			return fail(stderr, fmt.Errorf("reset vault: %w", err))
		}
		fmt.Fprintln(stdout, "Vault cleared. No saved connection referenced a stored credential; connections were kept.")
		return 0
	}

	if !assumeYes && !confirmReset(stdin, stdout, fmt.Sprintf(
		"Clear stored credentials for %d connection(s) (%s)?\n"+
			"This includes passwords and private-key passphrases; the connections are kept [y/N]: ",
		len(withSecrets), strings.Join(withSecrets, ", "))) {
		fmt.Fprintln(stdout, "Aborted; nothing was changed.")
		return 0
	}
	if err := stopVaultBroker(); err != nil {
		return fail(stderr, fmt.Errorf("stop broker before reset: %w", err))
	}

	err = withUnchangedRegistry(d, reg, false, func(current profile.Registry) error {
		original := cloneRegistry(current)
		for _, name := range withSecrets {
			p := current.Profiles[name]
			p.SecretRef = ""
			if err := current.Set(p); err != nil {
				return fmt.Errorf("update connection %q: %w", name, err)
			}
		}
		if err := d.store.Save(current); err != nil {
			return fmt.Errorf("save connections: %w", err)
		}
		if err := resetVault(d.secrets, false); err != nil {
			if rollbackErr := d.store.Save(original); rollbackErr != nil {
				return fmt.Errorf("reset vault: %v; restore connection references: %w", err, rollbackErr)
			}
			return fmt.Errorf("reset vault: %w", err)
		}
		return nil
	})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Vault cleared. Kept %d connection(s); cleared stored credentials for: %s\n",
		len(reg.Profiles), strings.Join(withSecrets, ", "))
	fmt.Fprintln(stdout, "Connections will use available SSH keys or the agent until credentials are stored again.")
	return 0
}

func withUnchangedRegistry(d deps, expected profile.Registry, expectUnreadable bool, fn func(profile.Registry) error) error {
	return statelock.WithLock(func() error {
		current, err := d.store.Load()
		if expectUnreadable {
			if errors.Is(err, profile.ErrConfigUnreadable) {
				return fn(profile.Registry{})
			}
			return errors.New("saved connections changed while reset was awaiting confirmation; run the command again")
		}
		if err != nil {
			return fmt.Errorf("read connections: %w", err)
		}
		if !reflect.DeepEqual(current, expected) {
			return errors.New("saved connections changed while reset was awaiting confirmation; run the command again")
		}
		return fn(current)
	})
}

func fullWipe(d deps) error {
	if err := d.store.Remove(); err != nil {
		return fmt.Errorf("remove connections: %w", err)
	}
	if err := resetVault(d.secrets, true); err != nil {
		return fmt.Errorf("reset vault: %w", err)
	}
	return nil
}

func printFullWipe(stdout io.Writer) {
	fmt.Fprintln(stdout, "Saved connections and local vault files removed. Start fresh with `corv add <name> <user@host>`.")
	fmt.Fprintln(stdout, "Externally provisioned OS keychain entries were not modified.")
}

func cloneRegistry(reg profile.Registry) profile.Registry {
	clone := profile.Registry{Profiles: make(map[string]profile.Profile, len(reg.Profiles))}
	for name, p := range reg.Profiles {
		clone.Profiles[name] = p
	}
	return clone
}

func profilesWithSecrets(reg profile.Registry) []string {
	var names []string
	for name, p := range reg.Profiles {
		if p.SecretRef != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func confirmReset(stdin io.Reader, stdout io.Writer, prompt string) bool {
	fmt.Fprint(stdout, prompt)
	sc := bufio.NewScanner(stdin)
	if sc.Scan() {
		answer := strings.ToLower(strings.TrimSpace(sc.Text()))
		return answer == "y" || answer == "yes"
	}
	return false
}
