package sshconn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/khalid-src/corv-client/internal/output"
)

const (
	channelOpenAttempts = 5
	channelRetryBackoff = 100 * time.Millisecond
)

// Exec runs a single command over the connection and returns a cleaned,
// bounded Result. The exit code comes from the SSH protocol itself, so it
// is exact - no sentinel parsing. timeout bounds the run (0 = none).
func (c *Conn) Exec(ctx context.Context, command []string, timeout time.Duration, opt output.Options) Result {
	stdout := output.New(opt)
	stderr := output.New(opt)

	start := time.Now()
	exit, kind, started := c.runOne(ctx, CommandString(command), nil, stdout, stderr, timeout)

	return Result{
		ExitCode:   exit,
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		Duration:   time.Since(start),
		TimedOut:   kind == ErrTimeout,
		Kind:       kind,
		Started:    started,
		Highlights: mergeSignals(stdout.Signals(), stderr.Signals()),
	}
}

// mergeSignals combines stdout and stderr highlights, deduping and capping.
func mergeSignals(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(a, b...) {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= 10 {
			break
		}
	}
	return out
}

// runOne runs cmd and reports the exit code, an ErrorKind, and whether the
// exec request may have reached the remote.
func (c *Conn) runOne(ctx context.Context, cmd string, stdin []byte, stdout, stderr io.Writer, timeout time.Duration) (int, ErrorKind, bool) {
	client := c.target()
	if client == nil {
		return 1, ErrDisconnect, false
	}

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	if err := c.acquireChannel(ctx); err != nil {
		return 124, ErrTimeout, false
	}
	defer c.releaseChannel()

	session, err := c.openSession(ctx, client)
	if err != nil {
		if ctx.Err() != nil {
			return 124, ErrTimeout, false
		}
		return 1, c.classifyChannelErr(err), false
	}
	defer session.Close()
	if stdin != nil {
		session.Stdin = bytes.NewReader(stdin)
	}
	session.Stdout = stdout
	session.Stderr = stderr

	startDone := make(chan error, 1)
	go func() {
		startDone <- session.Start(cmd)
	}()
	select {
	case <-ctx.Done():
		_ = c.Close()
		<-startDone
		return 124, ErrTimeout, true
	case err := <-startDone:
		if err != nil {
			return 1, c.classifyChannelErr(err), true
		}
	}

	done := make(chan error, 1)
	go func() { done <- session.Wait() }()

	select {
	case <-ctx.Done():
		// OpenSSH's sshd ignores SSH "signal" requests and keeps the channel
		// open until the command finishes, so closing just the session would
		// still block. Tear down the whole connection: this unblocks Wait
		// promptly and stops the library's output-copy goroutines, so reading
		// the filters after <-done is race-free. The broker redials on the
		// next command, so a timed-out command does not wedge the profile.
		_ = c.Close()
		<-done
		return 124, ErrTimeout, true
	case err := <-done:
		exit, kind := exitFromError(err)
		return exit, kind, true
	}
}

func (c *Conn) openSession(ctx context.Context, client *ssh.Client) (*ssh.Session, error) {
	var lastErr error
	for attempt := 0; attempt < channelOpenAttempts; attempt++ {
		type sessionResult struct {
			session *ssh.Session
			err     error
		}
		sessionDone := make(chan sessionResult, 1)
		go func() {
			session, err := client.NewSession()
			sessionDone <- sessionResult{session: session, err: err}
		}()

		select {
		case <-ctx.Done():
			_ = c.Close()
			result := <-sessionDone
			if result.session != nil {
				_ = result.session.Close()
			}
			return nil, ctx.Err()
		case result := <-sessionDone:
			if result.err == nil {
				return result.session, nil
			}
			lastErr = result.err
			if !isChannelResourceExhausted(result.err) {
				return nil, result.err
			}
		}

		if attempt == channelOpenAttempts-1 {
			break
		}
		timer := time.NewTimer(channelRetryBackoff * time.Duration(attempt+1))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}

func (c *Conn) classifyChannelErr(err error) ErrorKind {
	kind := classifyChannelError(err)
	if kind == ErrSSH && !c.Alive() {
		return ErrDisconnect
	}
	return kind
}

func exitFromError(err error) (int, ErrorKind) {
	if err == nil {
		return 0, ErrNone
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus(), ErrNone
	}
	var missing *ssh.ExitMissingError
	if errors.As(err, &missing) {
		// Connection dropped before the exit status arrived.
		return 1, ErrDisconnect
	}
	return 1, classifyErr(err)
}
