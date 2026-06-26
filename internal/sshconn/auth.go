package sshconn

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// defaultKeyNames are the private keys OpenSSH would try by default when no
// identity is configured.
var defaultKeyNames = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

// authMethods assembles the authentication methods to offer, in the order a
// user expects: an explicit identity file, then ssh-agent, then default
// keys, then password. Passphrase unlocks private keys; password is used for
// SSH password and keyboard-interactive authentication.
func authMethods(identityFile, passphrase, password string) ([]ssh.AuthMethod, []io.Closer, error) {
	var methods []ssh.AuthMethod
	var closers []io.Closer

	if identityFile != "" {
		signer, err := loadKey(identityFile, passphrase)
		if err != nil {
			return nil, nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if a, closer := agentMethod(); a != nil {
		methods = append(methods, a)
		closers = append(closers, closer)
	}

	if identityFile == "" {
		if signers := defaultKeySigners(passphrase); len(signers) > 0 {
			methods = append(methods, ssh.PublicKeys(signers...))
		}
	}

	if password != "" {
		methods = append(methods, ssh.Password(password))
		// Some servers drive password auth via keyboard-interactive.
		methods = append(methods, ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}))
	}

	if len(methods) == 0 {
		return nil, closers, errors.New("no authentication methods available (no key, agent, or password)")
	}
	return methods, closers, nil
}

// agentMethod returns an ssh-agent-backed auth method, or nil if no agent is
// reachable. SSH_AUTH_SOCK is the standard Unix discovery path; Windows
// named-pipe agents are handled in agent_windows.go.
func agentMethod() (ssh.AuthMethod, io.Closer) {
	conn, err := dialAgent()
	if err != nil {
		return nil, nil
	}
	client := agent.NewClient(conn)
	return ssh.PublicKeysCallback(client.Signers), conn
}

func loadKey(path, passphrase string) (ssh.Signer, error) {
	data, err := os.ReadFile(expandHome(path))
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err == nil {
		return signer, nil
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) && passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
	}
	return nil, err
}

func defaultKeySigners(passphrase string) []ssh.Signer {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var signers []ssh.Signer
	for _, name := range defaultKeyNames {
		signer, err := loadKey(filepath.Join(home, ".ssh", name), passphrase)
		if err == nil {
			signers = append(signers, signer)
		}
	}
	return signers
}

func expandHome(p string) string {
	if p == "~" || len(p) >= 2 && p[:2] == "~/" {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
