package sshconn

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// hostKeyCallback returns a verifier backed by the user's standard
// ~/.ssh/known_hosts file (shared with OpenSSH). A changed key is always
// refused. An unknown key is refused unless allowNew is set and prompt
// approves it, in which case it is recorded for next time.
func hostKeyCallback(allowNew bool, prompt func(host, fingerprint string) bool) (ssh.HostKeyCallback, error) {
	path, err := knownHostsPath()
	if err != nil {
		return nil, err
	}
	base, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("read known_hosts: %w", err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := base(hostname, remote, key)
		if err == nil {
			return nil
		}

		var ke *knownhosts.KeyError
		if !errors.As(err, &ke) {
			return err
		}
		if len(ke.Want) > 0 {
			// A different key is already pinned: never silently trust it.
			return &HostKeyError{Host: hostname, Changed: true, err: err}
		}
		// Unknown host.
		fp := ssh.FingerprintSHA256(key)
		if allowNew && prompt != nil && prompt(hostname, fp) {
			if aerr := appendKnownHost(path, hostname, remote, key); aerr != nil {
				return aerr
			}
			return nil
		}
		return &HostKeyError{Host: hostname, err: err}
	}, nil
}

func knownHostsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "known_hosts")
	// knownhosts.New requires the file to exist.
	f, err := os.OpenFile(path, os.O_CREATE, 0o600)
	if err != nil {
		return "", err
	}
	_ = f.Close()
	return path, nil
}

func appendKnownHost(path, hostname string, remote net.Addr, key ssh.PublicKey) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	addrs := []string{knownhosts.Normalize(hostname)}
	if usableKnownHostRemote(remote) {
		if r := knownhosts.Normalize(remote.String()); r != addrs[0] {
			addrs = append(addrs, r)
		}
	}
	line := knownhosts.Line(addrs, key)
	_, err = fmt.Fprintln(f, line)
	return err
}

func usableKnownHostRemote(remote net.Addr) bool {
	if remote == nil {
		return false
	}
	if tcp, ok := remote.(*net.TCPAddr); ok {
		return tcp.Port != 0 && tcp.IP != nil && !tcp.IP.IsUnspecified()
	}
	return true
}
