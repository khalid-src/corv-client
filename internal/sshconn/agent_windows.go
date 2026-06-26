//go:build windows

package sshconn

import (
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

const windowsAgentPipe = `\\.\pipe\openssh-ssh-agent`

// dialAgent connects to the Windows OpenSSH agent named pipe.
func dialAgent() (net.Conn, error) {
	timeout := 500 * time.Millisecond
	return winio.DialPipe(windowsAgentPipe, &timeout)
}
