// Package sshconn is Corv's SSH transport, built on the maintained Go SSH
// library (golang.org/x/crypto/ssh). It opens and authenticates a
// connection to a machine and runs commands or interactive shells over it.
//
// Using a library rather than shelling out to the OpenSSH binary is what
// lets Corv hold one connection open per machine and reuse it across
// commands identically on every OS - including Windows, whose OpenSSH
// client cannot multiplex. The remote server still gets nothing but normal
// SSH; Corv installs nothing there.
package sshconn

import (
	"errors"
	"strings"
	"time"
)

// Classify maps any error produced by this package onto a stable ErrorKind.
func Classify(err error) ErrorKind {
	var hk *HostKeyError
	if errors.As(err, &hk) {
		return ErrHostKey
	}
	return classifyErr(err)
}

// ErrorKind is a stable, machine-readable category for the common ways an
// SSH operation can fail, so callers (and LLMs) get a predictable signal.
type ErrorKind string

const (
	ErrNone              ErrorKind = ""
	ErrAuth              ErrorKind = "auth_failed"
	ErrUnknownHost       ErrorKind = "unknown_host"
	ErrUnreachable       ErrorKind = "unreachable"
	ErrHostKey           ErrorKind = "host_key"
	ErrTimeout           ErrorKind = "timeout"
	ErrDisconnect        ErrorKind = "disconnected"
	ErrResourceExhausted ErrorKind = "resource_exhausted"
	ErrSSH               ErrorKind = "ssh_error"
)

// Result is the outcome of a single non-interactive command. Stdout and
// Stderr are already cleaned and bounded by the output broker.
type Result struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Duration time.Duration
	TimedOut bool
	Kind     ErrorKind

	// Highlights are notable lines (errors/warnings) from the full output,
	// surfaced even when the bounded view omits them and even on exit 0.
	Highlights []string

	// Started reports whether the exec request may have reached the remote. It
	// is false only when failure happened before the request was sent, which is
	// the only case where an automatic retry cannot duplicate side effects.
	Started bool
}

// OK reports whether the command ran and exited zero.
func (r Result) OK() bool { return r.Kind == ErrNone && r.ExitCode == 0 }

// classifyErr maps a transport/dial error onto an ErrorKind.
func classifyErr(err error) ErrorKind {
	if err == nil {
		return ErrNone
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "knownhosts") ||
		strings.Contains(s, "host key") ||
		strings.Contains(s, "key mismatch"):
		return ErrHostKey
	case strings.Contains(s, "unable to authenticate") ||
		strings.Contains(s, "no supported methods") ||
		strings.Contains(s, "no authentication methods") ||
		strings.Contains(s, "permission denied") ||
		strings.Contains(s, "handshake failed"):
		return ErrAuth
	case strings.Contains(s, "no such host") ||
		strings.Contains(s, "could not resolve"):
		return ErrUnknownHost
	case strings.Contains(s, "connection refused") ||
		strings.Contains(s, "actively refused") || // Windows phrasing
		strings.Contains(s, "no connection could be made") ||
		strings.Contains(s, "no route to host") ||
		strings.Contains(s, "network is unreachable") ||
		strings.Contains(s, "host is unreachable"):
		return ErrUnreachable
	case strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "deadline exceeded") ||
		strings.Contains(s, "timed out") ||
		strings.Contains(s, "did not properly respond"): // Windows phrasing
		return ErrTimeout
	case strings.Contains(s, "eof") ||
		strings.Contains(s, "disconnected") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "use of closed"):
		return ErrDisconnect
	default:
		return ErrSSH
	}
}

func classifyChannelError(err error) ErrorKind {
	if isChannelResourceExhausted(err) {
		return ErrResourceExhausted
	}
	return classifyErr(err)
}

func isChannelResourceExhausted(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, phrase := range []string{
		"open failed",
		"administratively prohibited",
		"resource shortage",
		"maximum",
		"too many",
	} {
		if strings.Contains(message, phrase) {
			return true
		}
	}
	return false
}

// HostKeyError is returned by Dial when the host key is unknown or has
// changed, so the caller can decide whether to prompt or refuse.
type HostKeyError struct {
	Host    string
	Changed bool // true if a different key was already pinned (dangerous)
	err     error
}

func (e *HostKeyError) Error() string { return e.err.Error() }
func (e *HostKeyError) Unwrap() error { return e.err }
