package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSaveJobRegistryFailureKeepsPreviousFile(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	original := jobRegistry{Jobs: map[string]jobRecord{
		"old": {Key: "old", RunID: "0000000000000000-aa", Profile: "srv1", Command: "old"},
	}}
	if err := saveJobRegistry(original); err != nil {
		t.Fatal(err)
	}
	path, err := jobsFile()
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	originalWrite := writeJobFile
	writeJobFile = func(string, []byte, os.FileMode) error {
		return errors.New("replace failed")
	}
	t.Cleanup(func() { writeJobFile = originalWrite })
	changed := jobRegistry{Jobs: map[string]jobRecord{
		"new": {Key: "new", RunID: "0000000000000000-bb", Profile: "srv1", Command: "new"},
	}}
	if err := saveJobRegistry(changed); err == nil {
		t.Fatal("expected save failure")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed save changed the existing job registry")
	}
}

func TestJobRegistryDoesNotPersistCommandPayload(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	command := strings.Repeat("large-command;", 1<<16)
	j := newJob(command, "fingerprint")
	j.key = jobKey("srv1", command)
	j.started = true
	j.startedAt = time.Now()
	j.status = jobStatusRunning
	record := newJobRecord("srv1", j)
	if record.Command != "" || record.Key != j.key {
		t.Fatalf("record persisted command payload: key=%q command bytes=%d", record.Key, len(record.Command))
	}
	registry := jobRegistry{Jobs: map[string]jobRecord{record.Key: record}}
	for i := range 20 {
		record.Offset = int64(i * maxDeltaBytes)
		registry.Jobs[record.Key] = record
		if err := saveJobRegistry(registry); err != nil {
			t.Fatal(err)
		}
	}
	path, err := jobsFile()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 4096 {
		t.Fatalf("jobs registry grew to %d bytes for a %d-byte command", info.Size(), len(command))
	}
}

func TestKeyedJobPersistsHashesWithoutRawKey(t *testing.T) {
	command := "perform sensitive deployment"
	runKey := "customer-change-42"
	j := newJob(command, "fingerprint")
	j.key = keyedJobKey("srv1", runKey)
	j.commandHash = valueHash(command)
	j.runKeyHash = valueHash(runKey)
	rec := newJobRecord("srv1", j)
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), runKey) || strings.Contains(string(data), command) {
		t.Fatalf("persisted record contains raw key or command: %s", data)
	}
	if rec.CommandHash == "" || rec.RunKeyHash == "" || rec.Key != j.key {
		t.Fatalf("record = %#v", rec)
	}
}

func TestJobRecordPersistsTerminalExitCode(t *testing.T) {
	j := newJob("false", "fingerprint")
	j.done = true
	j.status = jobStatusDone
	j.exitCode = 23
	j.durationMS = 8123
	j.finishedAt = time.Now().UTC()

	rec := newJobRecord("srv1", j)
	if rec.ExitCode != 23 {
		t.Fatalf("exit code = %d, want 23", rec.ExitCode)
	}
	restored := recordToJob(rec)
	if restored.exitCode != 23 {
		t.Fatalf("restored exit code = %d, want 23", restored.exitCode)
	}
	if restored.durationMS != 8123 {
		t.Fatalf("restored duration = %d, want 8123", restored.durationMS)
	}
}

func TestJobRecordPersistsLastRemoteObservation(t *testing.T) {
	observed := time.Now().UTC().Truncate(time.Nanosecond)
	j := newJob("deploy", "fingerprint")
	j.lastSeenAt = observed

	rec := newJobRecord("srv1", j)
	if rec.LastSeenAt != observed.UnixNano() {
		t.Fatalf("last seen = %d, want %d", rec.LastSeenAt, observed.UnixNano())
	}
	restored := recordToJob(rec)
	if !restored.lastSeenAt.Equal(observed) {
		t.Fatalf("restored last seen = %s, want %s", restored.lastSeenAt, observed)
	}
}

func TestLoadLegacyJobRegistryWithoutLastSeen(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	path, err := jobsFile()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := `{"jobs":{"legacy":{"key":"legacy","run_id":"0000000000000000-aa","profile":"srv1","fingerprint":"fp","remote_dir":"/tmp/corv-jobs-1","log_path":"/tmp/corv-jobs-1/run.log","rc_path":"/tmp/corv-jobs-1/run.rc","offset":7,"started_at":1700000000,"status":"running","exit_code":0}}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	reg, err := loadJobRegistry()
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := reg.Jobs["legacy"]
	if !ok || rec.Status != jobStatusRunning || rec.LastSeenAt != 0 || rec.Offset != 7 {
		t.Fatalf("legacy record = %#v, found=%v", rec, ok)
	}
}
