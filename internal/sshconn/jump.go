package sshconn

import "github.com/khalid-src/corv-client/internal/profile"

// SecretFunc returns the stored password and key passphrase for a vault
// reference, or empty strings when none is available.
type SecretFunc func(secretRef string) (password, passphrase string)

// EnrichJumpChain fills in missing per-hop credentials from saved profiles.
// When a hop matches a saved profile - by name, or by host[:port] - it adopts
// that profile's endpoint, identity file, and vault secret, without ever
// overriding a value already set on the hop. secretFor resolves a profile's
// SecretRef to its password/passphrase; pass a closure over the vault.
//
// This is the single source of truth for jump-host auth resolution, shared by
// the interactive and broker dial paths.
func EnrichJumpChain(jumps []JumpHost, reg profile.Registry, secretFor SecretFunc) {
	for i := range jumps {
		p, ok := findJumpProfile(jumps[i], reg)
		if !ok {
			continue
		}
		user, host := splitTarget(p.Target)
		if _, named := reg.Get(jumps[i].Host); named {
			jumps[i].Host = host
			if jumps[i].Port == 0 {
				jumps[i].Port = p.Port
			}
		}
		if jumps[i].User == "" {
			jumps[i].User = user
		}
		if jumps[i].IdentityFile == "" {
			jumps[i].IdentityFile = p.IdentityFile
		}
		if p.SecretRef == "" || secretFor == nil {
			continue
		}
		password, passphrase := secretFor(p.SecretRef)
		if jumps[i].Password == "" {
			jumps[i].Password = password
		}
		if jumps[i].Passphrase == "" {
			jumps[i].Passphrase = passphrase
		}
	}
}

// findJumpProfile resolves a jump hop to a saved profile, first by profile
// name and then by matching endpoint (host, port, and user when specified).
func findJumpProfile(jump JumpHost, reg profile.Registry) (profile.Profile, bool) {
	if p, ok := reg.Get(jump.Host); ok {
		return p, true
	}
	for _, p := range reg.List() {
		user, host := splitTarget(p.Target)
		port := p.Port
		if port == 0 {
			port = 22
		}
		jumpPort := jump.Port
		if jumpPort == 0 {
			jumpPort = 22
		}
		if host == jump.Host && port == jumpPort && (jump.User == "" || jump.User == user) {
			return p, true
		}
	}
	return profile.Profile{}, false
}
