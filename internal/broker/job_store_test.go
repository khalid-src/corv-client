package broker

import (
	"bytes"
	"errors"
	"os"
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
