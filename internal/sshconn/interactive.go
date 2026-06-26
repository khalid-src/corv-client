package sshconn

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/muesli/cancelreader"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Interactive opens a shell on the remote and proxies it to the local
// terminal. The remote allocates the PTY, so the local OS needs no
// pseudo-terminal of its own - this works the same on Unix and Windows. It
// returns the shell's exit code.
func (c *Conn) Interactive() (int, error) {
	client := c.target()
	if client == nil {
		return 1, errors.New("connection is closed")
	}
	session, err := client.NewSession()
	if err != nil {
		return 1, err
	}
	defer session.Close()

	stdinFd := int(os.Stdin.Fd())
	isTTY := term.IsTerminal(stdinFd)

	w, h := 80, 24
	if isTTY {
		if cw, ch, err := term.GetSize(stdinFd); err == nil && cw > 0 && ch > 0 {
			w, h = cw, ch
		}
	}
	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}

	if isTTY {
		state, err := term.MakeRaw(stdinFd)
		if err == nil {
			var restoreOnce sync.Once
			restore := func() { restoreOnce.Do(func() { _ = term.Restore(stdinFd, state) }) }
			defer restore()
			stopSignals := restoreOnSignal(restore)
			defer stopSignals()
		}
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty(termType, h, w, modes); err != nil {
		return 1, err
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return 1, err
	}
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if err := session.Shell(); err != nil {
		return 1, err
	}

	// Forward local input to the remote shell through a cancelable reader. A
	// plain io.Copy(stdin, os.Stdin) goroutine would stay blocked reading
	// os.Stdin after the session ends, holding the console so a re-entered TUI
	// could never read input (a frozen home screen). Cancel it and wait for it
	// to release os.Stdin before returning.
	if cr, err := cancelreader.NewReader(os.Stdin); err == nil {
		copyDone := make(chan struct{})
		go func() { defer close(copyDone); _, _ = io.Copy(stdin, cr) }()
		defer func() { cr.Cancel(); <-copyDone }()
	} else {
		go func() { _, _ = io.Copy(stdin, os.Stdin) }()
	}
	stop := watchResize(session, stdinFd)
	defer stop()

	code, _ := exitFromError(session.Wait())
	return code, nil
}

func restoreOnSignal(restore func()) func() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-signals:
			restore()
			os.Exit(130)
		case <-done:
		}
	}()
	return func() {
		signal.Stop(signals)
		close(done)
	}
}
