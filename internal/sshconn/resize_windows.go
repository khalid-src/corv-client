//go:build windows

package sshconn

import (
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// watchResize polls the local terminal size on Windows (which has no
// SIGWINCH) and forwards changes to the remote PTY. It returns a stop
// function.
func watchResize(session *ssh.Session, fd int) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		lastW, lastH := 0, 0
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if w, h, err := term.GetSize(fd); err == nil && (w != lastW || h != lastH) {
					lastW, lastH = w, h
					_ = session.WindowChange(h, w)
				}
			}
		}
	}()
	return func() { close(done) }
}
