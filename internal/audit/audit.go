package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	RunID      string    `json:"run_id,omitempty"`
	Status     string    `json:"status,omitempty"`
}

type Log struct {
	path string
	mu   sync.Mutex
}

func NewLog(path string) *Log {
	return &Log{path: path}
}

func (l *Log) Append(entry Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.append(entry)
}

func (l *Log) append(entry Entry) error {
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
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.read(profile, tail)
}

func (l *Log) read(profile string, tail int) ([]Entry, error) {
	file, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if tail > 0 {
		entries := make([]Entry, 0, tail)
		err := scanEntriesReverse(file, func(entry Entry) bool {
			if profile == "" || entry.Profile == profile {
				entries = append(entries, entry)
			}
			return len(entries) < tail
		})
		if err != nil {
			return nil, err
		}
		for left, right := 0, len(entries)-1; left < right; left, right = left+1, right-1 {
			entries[left], entries[right] = entries[right], entries[left]
		}
		return entries, nil
	}

	var entries []Entry
	err = scanEntries(file, func(entry Entry) {
		if profile == "" || entry.Profile == profile {
			entries = append(entries, entry)
		}
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

const maxAuditLineBytes = 8 << 20

func scanEntries(input io.Reader, visit func(Entry)) error {
	reader := bufio.NewReader(input)
	line := make([]byte, 0, 4096)
	oversized := false
	for {
		fragment, err := reader.ReadSlice('\n')
		if !oversized {
			if len(line)+len(fragment) > maxAuditLineBytes {
				line = line[:0]
				oversized = true
			} else {
				line = append(line, fragment...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if !oversized && len(line) > 0 {
			line = bytes.TrimSuffix(line, []byte{'\n'})
			line = bytes.TrimSuffix(line, []byte{'\r'})
			var entry Entry
			if json.Unmarshal(line, &entry) == nil {
				visit(entry)
			}
		}
		line = line[:0]
		oversized = false
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

func scanEntriesReverse(file *os.File, visit func(Entry) bool) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	const blockSize = 64 * 1024
	position := info.Size()
	var segments [][]byte
	segmentBytes := 0
	droppingOversized := false
	visitLine := func(prefix []byte) bool {
		lineSize := len(prefix) + segmentBytes
		if lineSize > maxAuditLineBytes {
			return true
		}
		line := make([]byte, 0, lineSize)
		line = append(line, prefix...)
		for i := len(segments) - 1; i >= 0; i-- {
			line = append(line, segments[i]...)
		}
		entry, ok := decodeEntry(line)
		return !ok || visit(entry)
	}
	for position > 0 {
		readSize := int64(blockSize)
		if position < readSize {
			readSize = position
		}
		position -= readSize
		block := make([]byte, int(readSize))
		n, err := file.ReadAt(block, position)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		block = block[:n]
		end := len(block)
		for {
			newline := bytes.LastIndexByte(block[:end], '\n')
			if newline < 0 {
				break
			}
			if droppingOversized {
				droppingOversized = false
			} else if !visitLine(block[newline+1 : end]) {
				return nil
			}
			segments = nil
			segmentBytes = 0
			end = newline
		}
		if droppingOversized {
			continue
		}
		if end > 0 {
			segment := append([]byte(nil), block[:end]...)
			segments = append(segments, segment)
			segmentBytes += len(segment)
		}
		if segmentBytes > maxAuditLineBytes {
			segments = nil
			segmentBytes = 0
			droppingOversized = true
		}
	}
	if !droppingOversized {
		visitLine(nil)
	}
	return nil
}

func decodeEntry(line []byte) (Entry, bool) {
	line = bytes.TrimSuffix(line, []byte{'\n'})
	line = bytes.TrimSuffix(line, []byte{'\r'})
	if len(line) == 0 {
		return Entry{}, false
	}
	var entry Entry
	if json.Unmarshal(line, &entry) != nil {
		return Entry{}, false
	}
	return entry, true
}

// Complete appends the terminal outcome for a previously recorded detached run.
func (l *Log) Complete(runID string, startedAt, finishedAt time.Time, exitCode int) error {
	if runID == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	file, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	var started *Entry
	err = scanEntriesReverse(file, func(entry Entry) bool {
		if entry.RunID != runID {
			return true
		}
		if entry.Status == "completed" {
			return false
		}
		if entry.Status == "running" || (entry.Status == "" && entry.ExitCode == 75) {
			copy := entry
			started = &copy
			return false
		}
		return entry.Status != ""
	})
	if err != nil {
		return err
	}
	if started == nil {
		return nil
	}
	completed := *started
	completed.StartedAt = startedAt
	completed.FinishedAt = finishedAt
	completed.ExitCode = exitCode
	completed.DurationMS = finishedAt.Sub(startedAt).Milliseconds()
	completed.Error = ""
	completed.Status = "completed"
	return l.append(completed)
}

// Clear removes all recorded entries.
func (l *Log) Clear() error {
	l.mu.Lock()
	defer l.mu.Unlock()
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
