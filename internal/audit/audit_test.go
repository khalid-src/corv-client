package audit

import (
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
