// Package profile is the connection store: it defines saved SSH
// connections and persists them to a local JSON file. A Profile is the
// minimal set of facts Corv needs to reach a machine by name. Secrets are
// never stored here, only an opaque SecretRef into the vault.
package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Sealer encrypts and decrypts profile store bytes. The connection file is
// intentionally not human-readable; use `corv list` to inspect profiles.
type Sealer interface {
	Seal([]byte) ([]byte, error)
	Open([]byte) ([]byte, error)
}

// nameRE constrains profile names to a safe, shell- and filename-friendly
// set so a name can be used unquoted on a command line and as a key.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// Profile is a single saved connection. Target is the OpenSSH destination
// in user@host form (the user is optional). SecretRef, when set, points at
// a password in the vault; the password itself is never kept here.
type Profile struct {
	Name         string `json:"name"`
	Target       string `json:"target"`
	Port         int    `json:"port,omitempty"`
	IdentityFile string `json:"identity_file,omitempty"`
	SecretRef    string `json:"secret_ref,omitempty"`
	// ProxyJump is an OpenSSH-style jump specification used to reach Target
	// through one or more bastion hosts: a comma-separated list of
	// [user@]host[:port] hops. Empty means a direct connection.
	ProxyJump string `json:"proxy_jump,omitempty"`
}

// Registry is the in-memory set of profiles. It is decoupled from storage
// so it can be validated and tested without touching disk.
type Registry struct {
	Profiles map[string]Profile `json:"profiles"`
}

// Store persists a Registry to a single JSON file.
type Store struct {
	path   string
	sealer Sealer
}

// NewStore returns a Store backed by the file at path.
func NewStore(path string, sealer Sealer) *Store {
	return &Store{path: path, sealer: sealer}
}

// Load reads the registry from disk. A missing or empty file is treated as
// an empty registry rather than an error, so first run just works.
func (s *Store) Load() (Registry, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(data) == 0) {
		return Registry{Profiles: map[string]Profile{}}, nil
	}
	if err != nil {
		return Registry{}, err
	}
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		if s.sealer == nil {
			return Registry{}, errors.New("profile store sealer is required")
		}
		opened, err := s.sealer.Open(bytes.TrimSpace(data))
		if err != nil {
			return Registry{}, fmt.Errorf("decrypt config: %w", err)
		}
		data = opened
	}

	var reg Registry
	if err := json.Unmarshal(data, &reg); err != nil {
		return Registry{}, fmt.Errorf("read config: %w", err)
	}
	if reg.Profiles == nil {
		reg.Profiles = map[string]Profile{}
	}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		if raw, err := os.ReadFile(s.path); err == nil && bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
			if err := s.Save(reg); err != nil {
				return Registry{}, err
			}
		}
	}
	return reg, nil
}

// Save writes the registry atomically-ish with restrictive permissions.
func (s *Store) Save(reg Registry) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if s.sealer == nil {
		return errors.New("profile store sealer is required")
	}
	data, err = s.sealer.Seal(data)
	if err != nil {
		return fmt.Errorf("encrypt config: %w", err)
	}
	return os.WriteFile(s.path, data, 0o600)
}

// Set validates and inserts (or replaces) a profile keyed by name.
func (r *Registry) Set(p Profile) error {
	if r.Profiles == nil {
		r.Profiles = map[string]Profile{}
	}
	p.Name = strings.TrimSpace(p.Name)
	p.Target = strings.TrimSpace(p.Target)
	p.IdentityFile = strings.TrimSpace(p.IdentityFile)
	p.SecretRef = strings.TrimSpace(p.SecretRef)
	p.ProxyJump = strings.TrimSpace(p.ProxyJump)

	if !nameRE.MatchString(p.Name) {
		return fmt.Errorf("invalid profile name %q", p.Name)
	}
	if p.Target == "" {
		return errors.New("target is required")
	}
	if strings.ContainsAny(p.Target, "\r\n\t ") {
		return errors.New("target cannot contain whitespace")
	}
	if p.Port < 0 || p.Port > 65535 {
		return fmt.Errorf("invalid port: %d", p.Port)
	}

	r.Profiles[p.Name] = p
	return nil
}

// Get returns the profile with the given name.
func (r Registry) Get(name string) (Profile, bool) {
	p, ok := r.Profiles[name]
	return p, ok
}

// List returns all profiles sorted by name for stable output.
func (r Registry) List() []Profile {
	profiles := make([]Profile, 0, len(r.Profiles))
	for _, p := range r.Profiles {
		profiles = append(profiles, p)
	}
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})
	return profiles
}

// Remove deletes a profile by name, reporting whether it existed.
func (r *Registry) Remove(name string) bool {
	if r.Profiles == nil {
		return false
	}
	if _, ok := r.Profiles[name]; !ok {
		return false
	}
	delete(r.Profiles, name)
	return true
}
