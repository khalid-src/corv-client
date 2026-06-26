//go:build !windows

package sshconn

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// watchResize forwards local terminal size changes to the remote PTY via
// SIGWINCH. It returns a stop function.
func watchResize(session *ssh.Session, fd int) func() {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-sigc:
				if w, h, err := term.GetSize(fd); err == nil {
					_ = session.WindowChange(h, w)
				}
			}
		}
	}()
	return func() {
		signal.Stop(sigc)
		close(done)
	}
}
