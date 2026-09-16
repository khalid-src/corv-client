// Package broker is the small resident process that makes "the session
// stays open" real. It holds one authenticated SSH connection per profile
// and runs each command as a fresh channel over that warm connection, so an
// agent firing many commands pays the connection cost once, not every time -
// identically on every OS.
//
// The broker owns SSH connections only. It does not own a local
// pseudo-terminal, parse shell prompts, or keep remote shell state; commands
// are protocol-level exec requests with exact exit codes. Interactive shells
// do not go through the broker. This keeps its responsibilities narrow.
package broker

import "time"

// Op is the kind of request sent to the broker.
type Op string

const (
	OpPing     Op = "ping"     // liveness check
	OpExec     Op = "exec"     // run a command on a profile
	OpOutput   Op = "output"   // read a completed run log
	OpJobs     Op = "jobs"     // list active and retained runs
	OpClose    Op = "close"    // drop a profile's held connection
	OpList     Op = "list"     // list held connections
	OpStatus   Op = "status"   // describe held connections
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
	RunKey  string   `json:"run_key,omitempty"`
	// Wait carries the client's CORV_WAIT value so the synchronous wait window
	// can be set per invocation instead of only when the broker starts.
	Wait string `json:"wait,omitempty"`
}

// Response is the broker's reply.
type Response struct {
	OK              bool       `json:"ok"`
	ExitCode        int        `json:"exit_code,omitempty"`
	Stdout          string     `json:"stdout,omitempty"`
	Stderr          string     `json:"stderr,omitempty"`
	DurationMS      int64      `json:"duration_ms,omitempty"`
	Kind            string     `json:"kind,omitempty"`
	Error           string     `json:"error,omitempty"`
	Highlights      []string   `json:"highlights,omitempty"`
	Running         bool       `json:"running,omitempty"`
	RunID           string     `json:"run_id,omitempty"`
	Connection      string     `json:"connection,omitempty"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	Truncated       bool       `json:"truncated,omitempty"`
	RunMetadata     bool       `json:"run_metadata,omitempty"`
	OutputTruncated bool       `json:"output_truncated,omitempty"`
	Lossy           bool       `json:"lossy,omitempty"`
	OriginalBytes   int64      `json:"original_bytes,omitempty"`
	SavedBytes      int64      `json:"saved_bytes,omitempty"`
	ReturnedBytes   int64      `json:"returned_bytes,omitempty"`

	// Held lists active connections, for OpList.
	Held []HeldInfo `json:"held,omitempty"`
	// Connections describes active connections, for OpStatus.
	Connections []StatusInfo `json:"connections,omitempty"`
	// Runs lists active and recently retained detached runs.
	Runs []RunInfo `json:"runs,omitempty"`
}

// RunInfo describes one detached run without exposing connection details.
type RunInfo struct {
	RunID      string     `json:"run_id"`
	Connection string     `json:"connection"`
	Status     string     `json:"status"`
	Running    bool       `json:"running"`
	ExitCode   *int       `json:"exit_code,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Truncated  bool       `json:"truncated,omitempty"`
}

// StatusInfo describes one warm connection and its active work.
type StatusInfo struct {
	Name        string `json:"name"`
	Target      string `json:"target"`
	IdleMS      int64  `json:"idle_ms"`
	RunningJobs int    `json:"running_jobs"`
}

// HeldInfo describes one warm connection.
type HeldInfo struct {
	Name   string `json:"name"`
	Target string `json:"target"`
	IdleMS int64  `json:"idle_ms"`
}
