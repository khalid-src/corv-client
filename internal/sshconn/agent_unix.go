//go:build !windows

package sshconn

import (
	"errors"
	"net"
	"os"
)

// dialAgent connects to the running ssh-agent via SSH_AUTH_SOCK.
func dialAgent() (net.Conn, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, errors.New("no ssh-agent (SSH_AUTH_SOCK unset)")
	}
	return net.Dial("unix", sock)
}
