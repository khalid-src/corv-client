package sshconn

import (
	"bytes"
	"context"
	"time"
)

// RawResult is the outcome of a command whose stdout must be counted before
// the output broker cleans and bounds it.
type RawResult struct {
	ExitCode  int
	Stdout    []byte
	Stderr    []byte
	Duration  time.Duration
	Kind      ErrorKind
	Started   bool
	OutBytes  int64
	ErrBytes  int64
	Truncated bool
}

// OK reports whether the raw command ran and exited zero.
func (r RawResult) OK() bool { return r.Kind == ErrNone && r.ExitCode == 0 }

// ExecRaw runs command and captures at most maxBytes of each stream while
// still counting all bytes that passed through the SSH channel.
func (c *Conn) ExecRaw(ctx context.Context, command string, maxBytes int64) RawResult {
	return c.ExecRawStdin(ctx, command, nil, maxBytes)
}

// ExecRawStdin runs command with stdin and captures bounded output.
func (c *Conn) ExecRawStdin(ctx context.Context, command string, stdin []byte, maxBytes int64) RawResult {
	stdout := &limitBuffer{max: maxBytes}
	stderr := &limitBuffer{max: maxBytes}

	start := time.Now()
	exit, kind, started := c.runOne(ctx, command, stdin, stdout, stderr, 0)

	return RawResult{
		ExitCode:  exit,
		Stdout:    stdout.Bytes(),
		Stderr:    stderr.Bytes(),
		Duration:  time.Since(start),
		Kind:      kind,
		Started:   started,
		OutBytes:  stdout.Count(),
		ErrBytes:  stderr.Count(),
		Truncated: stdout.Truncated() || stderr.Truncated(),
	}
}

type limitBuffer struct {
	buf bytes.Buffer
	max int64
	n   int64
}

func (w *limitBuffer) Write(p []byte) (int, error) {
	n := len(p)
	w.n += int64(n)
	if w.max <= 0 {
		return n, nil
	}
	remain := w.max - int64(w.buf.Len())
	if remain > 0 {
		buffered := p
		if int64(len(p)) > remain {
			buffered = p[:remain]
		}
		_, _ = w.buf.Write(buffered)
	}
	return n, nil
}

func (w *limitBuffer) Bytes() []byte { return w.buf.Bytes() }
func (w *limitBuffer) Count() int64  { return w.n }

func (w *limitBuffer) Truncated() bool {
	return w.max > 0 && w.n > w.max
}
