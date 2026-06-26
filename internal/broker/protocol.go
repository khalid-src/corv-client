// Package broker is the small resident process that makes "the session
// stays open" real. It holds one authenticated SSH connection per profile
// and runs each command as a fresh channel over that warm connection, so an
// agent firing many commands pays the connection cost once, not every time -
// identically on every OS.
//
// The broker owns SSH connections only. It does not own a local
// pseudo-terminal, parse shell prompts, or keep remote shell state; commands
// are protocol-level exec requests with exact exit codes. Interactive shells
// do not go through the broker. This keeps it lean and robust.
package broker

import "time"

// Op is the kind of request sent to the broker.
type Op string

const (
	OpPing     Op = "ping"     // liveness check
	OpExec     Op = "exec"     // run a command on a profile
	OpOutput   Op = "output"   // read a completed run log
	OpClose    Op = "close"    // drop a profile's held connection
	OpList     Op = "list"     // list held connections
	OpShutdown Op = "shutdown" // stop the broker
)

// Request is a single command to the broker. The broker resolves the
// profile and its secret locally by Name, so credentials never travel over
// the IPC channel.
type Request struct {
	Op      Op       `json:"op"`
	Name    string   `json:"name,omitempty"`
	Command []string `json:"command,omitempty"`
	RunID   string   `json:"run_id,omitempty"`
	Pattern string   `json:"pattern,omitempty"`
	// Wait carries the client's CORV_WAIT value so the synchronous wait window
	// can be set per invocation instead of only when the broker starts.
	Wait string `json:"wait,omitempty"`
}

// Response is the broker's reply.
type Response struct {
	OK          bool       `json:"ok"`
	ExitCode    int        `json:"exit_code,omitempty"`
	Stdout      string     `json:"stdout,omitempty"`
	Stderr      string     `json:"stderr,omitempty"`
	DurationMS  int64      `json:"duration_ms,omitempty"`
	Kind        string     `json:"kind,omitempty"`
	Error       string     `json:"error,omitempty"`
	Highlights  []string   `json:"highlights,omitempty"`
	Running     bool       `json:"running,omitempty"`
	RunID       string     `json:"run_id,omitempty"`
	Connection  string     `json:"connection,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	Truncated   bool       `json:"truncated,omitempty"`
	RunMetadata bool       `json:"run_metadata,omitempty"`

	// Held lists active connections, for OpList.
	Held []HeldInfo `json:"held,omitempty"`
}

// HeldInfo describes one warm connection.
type HeldInfo struct {
	Name   string `json:"name"`
	Target string `json:"target"`
	IdleMS int64  `json:"idle_ms"`
}
