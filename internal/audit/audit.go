package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Entry struct {
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Profile    string    `json:"profile"`
	Target     string    `json:"target"`
	Command    string    `json:"command"`
	ExitCode   int       `json:"exit_code"`
	DurationMS int64     `json:"duration_ms"`
	Error      string    `json:"error,omitempty"`
}

type Log struct {
	path string
}

func NewLog(path string) *Log {
	return &Log{path: path}
}

func (l *Log) Append(entry Entry) error {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	// Bound the stored fields so a large --stdin command never writes a
	// multi-megabyte line that would later be unreadable or memory-heavy.
	entry.Command = truncateField(entry.Command, maxLoggedField)
	entry.Error = truncateField(entry.Error, maxLoggedField)

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = file.Write(data)
	return err
}

// maxLoggedField caps any single stored field so one entry stays a sane size.
const maxLoggedField = 4096

func truncateField(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + " ...[truncated]"
}

func (l *Log) Read(profile string, tail int) ([]Entry, error) {
	file, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []Entry
	// A bufio.Reader has no token-size limit, so one oversized historical line
	// (e.g. a logged large command) is read and skipped rather than failing the
	// whole view, which a bufio.Scanner would do with ErrTooLong.
	reader := bufio.NewReader(file)
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 {
			var entry Entry
			if json.Unmarshal([]byte(strings.TrimRight(line, "\n")), &entry) == nil {
				if profile == "" || entry.Profile == profile {
					entries = append(entries, entry)
				}
			}
		}
		if readErr != nil {
			break
		}
	}
	if tail > 0 && len(entries) > tail {
		entries = entries[len(entries)-tail:]
	}
	return entries, nil
}

// Clear removes all recorded entries.
func (l *Log) Clear() error {
	err := os.Remove(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// OneLine collapses a possibly multi-line command into a single readable line
// for log listings: the first non-empty line, with an ellipsis when more was
// trimmed (further lines, or an over-long line).
func OneLine(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	trimmed := false
	if i := strings.IndexByte(cmd, '\n'); i >= 0 {
		cmd = cmd[:i]
		trimmed = true
	}
	cmd = strings.TrimSpace(cmd)
	const max = 100
	if len(cmd) > max {
		cmd = strings.TrimSpace(cmd[:max])
		trimmed = true
	}
	if trimmed {
		cmd += " ..."
	}
	return cmd
}
