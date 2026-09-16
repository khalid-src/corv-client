package audit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogReadFiltersAndTails(t *testing.T) {
	log := NewLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	now := time.Now()

	entries := []Entry{
		{StartedAt: now, Profile: "a", Command: "one", ExitCode: 0},
		{StartedAt: now, Profile: "b", Command: "two", ExitCode: 0},
		{StartedAt: now, Profile: "a", Command: "three", ExitCode: 1},
	}
	for _, entry := range entries {
		if err := log.Append(entry); err != nil {
			t.Fatal(err)
		}
	}

	got, err := log.Read("a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Command != "three" {
		t.Fatalf("unexpected entries: %#v", got)
	}
}

func TestLogReadTailUsesLatestMatchingEntries(t *testing.T) {
	log := NewLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	for i := 0; i < 1000; i++ {
		profile := "a"
		if i%3 == 0 {
			profile = "b"
		}
		if err := log.Append(Entry{StartedAt: time.Now(), Profile: profile, Command: fmt.Sprintf("command-%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := log.Read("a", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Command != "command-997" || entries[1].Command != "command-998" {
		t.Fatalf("entries = %#v", entries)
	}
}

func TestLogAppendTruncatesLargeCommand(t *testing.T) {
	log := NewLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	command := strings.Repeat("x", 128*1024)
	if err := log.Append(Entry{StartedAt: time.Now(), Profile: "srv", Command: command}); err != nil {
		t.Fatal(err)
	}

	entries, err := log.Read("srv", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if len(entries[0].Command) > maxLoggedField+64 {
		t.Fatalf("command was not truncated on store: %d bytes", len(entries[0].Command))
	}
	if !strings.Contains(entries[0].Command, "[truncated]") {
		t.Fatal("truncated command should be marked")
	}
}

// TestLogReadSurvivesOversizedLine guards the logs view: a single huge historical
// line (e.g. a previously logged large command) must not fail the whole read.
func TestLogReadSurvivesOversizedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	huge := `{"profile":"srv","command":"` + strings.Repeat("x", 9<<20) + `"}` + "\n"
	good := `{"profile":"srv","command":"ok"}` + "\n"
	if err := os.WriteFile(path, []byte(huge+good), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := NewLog(path).Read("srv", 0)
	if err != nil {
		t.Fatalf("read failed on oversized line: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no entries read past the oversized line")
	}
	if entries[len(entries)-1].Command != "ok" {
		t.Fatalf("did not recover the good entry after the oversized line: %#v", entries)
	}
}

func TestLogReadTailSkipsOversizedLatestLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	good := `{"profile":"srv","command":"ok"}` + "\n"
	huge := `{"profile":"srv","command":"` + strings.Repeat("x", 9<<20) + `"}` + "\n"
	if err := os.WriteFile(path, []byte(good+huge), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := NewLog(path).Read("srv", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Command != "ok" {
		t.Fatalf("entries = %#v", entries)
	}
}

func TestCompleteAppendsDetachedRunOutcomeOnce(t *testing.T) {
	log := NewLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	started := time.Now().UTC().Add(-time.Minute)
	finished := started.Add(45 * time.Second)
	if err := log.Append(Entry{
		StartedAt: finished.Add(time.Second),
		Profile:   "srv1",
		Command:   "deploy",
		ExitCode:  75,
		RunID:     "run-123",
		Status:    "running",
	}); err != nil {
		t.Fatal(err)
	}
	if err := log.Complete("run-123", started, finished, 23); err != nil {
		t.Fatal(err)
	}
	if err := log.Complete("run-123", started, finished, 23); err != nil {
		t.Fatal(err)
	}
	entries, err := log.Read("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	got := entries[1]
	if got.RunID != "run-123" || got.ExitCode != 23 || !got.FinishedAt.Equal(finished) || got.DurationMS != 45000 {
		t.Fatalf("completion = %#v", got)
	}
}

func TestCompleteDoesNotTreatRemoteExit75AsRunning(t *testing.T) {
	log := NewLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	now := time.Now().UTC()
	if err := log.Append(Entry{
		StartedAt: now.Add(-time.Second), FinishedAt: now,
		Profile: "srv1", Command: "remote-exit-75", ExitCode: 75,
		RunID: "run-75", Status: "completed",
	}); err != nil {
		t.Fatal(err)
	}
	if err := log.Complete("run-75", now.Add(-time.Second), now, 75); err != nil {
		t.Fatal(err)
	}
	entries, err := log.Read("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
}

func TestCompleteSkipsPendingFinalizationError(t *testing.T) {
	log := NewLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	started := time.Now().UTC().Add(-time.Minute)
	finished := started.Add(30 * time.Second)
	for _, entry := range []Entry{
		{StartedAt: started, Profile: "srv1", Command: "deploy", ExitCode: 75, RunID: "run-pending", Status: "running"},
		{StartedAt: finished, Profile: "srv1", Command: "deploy", ExitCode: 1, RunID: "run-pending", Status: "pending", Error: "local_error"},
	} {
		if err := log.Append(entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Complete("run-pending", started, finished, 0); err != nil {
		t.Fatal(err)
	}
	entries, err := log.Read("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[2].Status != "completed" || entries[2].ExitCode != 0 {
		t.Fatalf("entries = %#v", entries)
	}
}

type failingReader struct {
	data []byte
	done bool
	err  error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		return copy(p, r.data), nil
	}
	return 0, r.err
}

func TestScanEntriesSurfacesReadFailure(t *testing.T) {
	want := errors.New("storage read failed")
	err := scanEntries(&failingReader{
		data: []byte("{\"profile\":\"srv\"}\n"),
		err:  want,
	}, func(Entry) {})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

var _ io.Reader = (*failingReader)(nil)
