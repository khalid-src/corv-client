package broker

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/khalid-src/corv-client/internal/paths"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/sshconn"
	"github.com/khalid-src/corv-client/internal/vault"
	"github.com/khalid-src/corv-client/internal/version"
)

type testSSHServer struct {
	addr    string
	hostKey ssh.PublicKey
	dials   *atomic.Int32
	cleanup func()
}

func TestBrokerExecReusesConnection(t *testing.T) {
	jobs := newAsyncJobTestHandler(func(cmd string) (string, int) {
		return "ran " + cmd + "\n", 7
	})
	server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer server.cleanup()
	startBrokerForTest(t, server)

	client := NewClient("unused")
	resp, err := client.Exec("srv1", []string{"echo", "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ExitCode != 7 || resp.Stdout != "ran echo hello\n" || resp.DurationMS < 0 {
		t.Fatalf("unexpected response: %#v", resp)
	}

	resp, err = client.Exec("srv1", []string{"hostname"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Stdout != "ran hostname\n" {
		t.Fatalf("unexpected stdout: %q", resp.Stdout)
	}
	if got := server.dials.Load(); got != 1 {
		t.Fatalf("SSH dials = %d, want 1", got)
	}
	if got := jobs.starts.Load(); got != 2 {
		t.Fatalf("job starts = %d, want 2", got)
	}
}

func TestBrokerProfileChangeDropsConnectionAndDetachedJob(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	t.Setenv("CORV_WAIT", "0s")
	resetBrokerTestHooks(t)

	jobsA := newAsyncJobTestHandler(func(string) (string, int) {
		return "host-a\n", 0
	})
	jobsA.rcAfter.Store(1000)
	hostA := startBrokerTestSSHServerStdin(t, false, jobsA.HandleStdin)
	defer hostA.cleanup()

	jobsB := newAsyncJobTestHandler(func(string) (string, int) {
		return "host-b\n", 0
	})
	hostB := startBrokerTestSSHServerStdin(t, false, jobsB.HandleStdin)
	defer hostB.cleanup()

	p, err := paths.Default()
	if err != nil {
		t.Fatal(err)
	}
	secrets := vault.New(p.VaultFile, p.VaultKey)
	store := profile.NewStore(p.ConfigFile, secrets)
	profileA := brokerTestProfile(t, "srv1", hostA)
	profileB := brokerTestProfile(t, "srv1", hostB)
	reg := profile.Registry{}
	if err := reg.Set(profileA); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(reg); err != nil {
		t.Fatal(err)
	}

	testDialOptions = func(p profile.Profile) sshconn.DialOptions {
		hostKey := hostA.hostKey
		if p.Port == profileB.Port {
			hostKey = hostB.hostKey
		}
		return sshconn.DialOptions{
			HostKey: ssh.FixedHostKey(hostKey),
			Auth:    []ssh.AuthMethod{ssh.Password("x")},
		}
	}

	errc := make(chan error, 1)
	go func() { errc <- Serve() }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if NewClient("unused").Running() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() { stopBrokerProcessForTest(t, errc) })

	client := NewClient("unused")
	first, err := client.Exec("srv1", []string{"same-command"})
	if err != nil {
		t.Fatal(err)
	}
	if !first.Running || first.Stdout != "host-a\n" {
		t.Fatalf("host A response = %#v", first)
	}

	reg = profile.Registry{}
	if err := reg.Set(profileB); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(reg); err != nil {
		t.Fatal(err)
	}

	second, err := client.Exec("srv1", []string{"same-command"})
	if err != nil {
		t.Fatal(err)
	}
	if second.Running || !second.OK || second.Stdout != "host-b\n" {
		t.Fatalf("host B response = %#v", second)
	}
	if second.RunID == first.RunID {
		t.Fatalf("changed profile reused run %s", first.RunID)
	}
	if got := hostA.dials.Load(); got != 1 {
		t.Fatalf("host A dials = %d, want 1", got)
	}
	if got := hostB.dials.Load(); got != 1 {
		t.Fatalf("host B dials = %d, want 1", got)
	}
	if got := jobsA.starts.Load(); got != 1 {
		t.Fatalf("host A starts = %d, want 1", got)
	}
	if got := jobsB.starts.Load(); got != 1 {
		t.Fatalf("host B starts = %d, want 1", got)
	}
}

func TestStaleJobCannotOverwriteCurrentProfileRecord(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	e := &entry{fingerprint: "new", jobs: map[string]*job{}}
	e.cond = sync.NewCond(&e.mu)
	current := newJob("deploy", "new")
	current.started = true
	current.startedAt = time.Now()
	current.status = jobStatusRunning
	stale := newJob("deploy", "old")
	stale.started = true
	stale.startedAt = time.Now()
	stale.status = jobStatusRunning
	e.jobs[current.command] = current

	s := &server{
		entries: map[string]*entry{"srv1": e},
		jobs:    jobRegistry{Jobs: map[string]jobRecord{}},
	}
	if err := s.savePersistedJob("srv1", current); err != nil {
		t.Fatal(err)
	}
	if err := s.savePersistedJob("srv1", stale); err != nil {
		t.Fatal(err)
	}

	rec, ok := s.persistedJob("srv1", "deploy")
	if !ok {
		t.Fatal("current job record missing")
	}
	if rec.RunID != current.id || rec.Fingerprint != current.fingerprint {
		t.Fatalf("stale job overwrote current record: %#v", rec)
	}
}

func TestBrokerRedialsAfterDroppedConnection(t *testing.T) {
	jobs := newAsyncJobTestHandler(func(cmd string) (string, int) {
		return "ran " + cmd + "\n", 0
	})
	server := startBrokerTestSSHServerStdin(t, true, jobs.HandleStdin)
	defer server.cleanup()
	startBrokerForTest(t, server)

	client := NewClient("unused")
	if resp, err := client.Exec("srv1", []string{"first"}); err != nil || !resp.OK {
		t.Fatalf("first exec resp=%#v err=%v", resp, err)
	}
	resp, err := client.Exec("srv1", []string{"second"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Stdout != "ran second\n" {
		t.Fatalf("second exec response: %#v", resp)
	}
	if got := server.dials.Load(); got < 2 {
		t.Fatalf("SSH dials = %d, want at least 2 after redial", got)
	}
}

func TestBrokerAsyncJobReattachesWithoutRestartAndAdvancesDelta(t *testing.T) {
	t.Setenv("CORV_WAIT", "0s")
	jobs := newAsyncJobTestHandler(func(cmd string) (string, int) {
		return "first\nsecond\n", 0
	})
	jobs.rcAfter.Store(1000)
	server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer server.cleanup()
	startBrokerForTest(t, server)

	client := NewClient("unused")
	resp, err := client.Exec("srv1", []string{"long-task"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Running || resp.Stdout != "first\nsecond\n" {
		t.Fatalf("first response = %#v", resp)
	}

	jobs.rcAfter.Store(jobs.rcCalls.Load() + 1)
	resp, err = client.Exec("srv1", []string{"long-task"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Running || !resp.OK || resp.Stdout != "" {
		t.Fatalf("second response = %#v", resp)
	}
	if got := jobs.starts.Load(); got != 1 {
		t.Fatalf("job starts = %d, want 1", got)
	}
}

func TestBrokerIdenticalFailedCommandStartsFreshRun(t *testing.T) {
	jobs := newAsyncJobTestHandler(func(string) (string, int) {
		return "failed\n", 9
	})
	server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer server.cleanup()
	startBrokerForTest(t, server)

	client := NewClient("unused")
	first, err := client.Exec("srv1", []string{"repeat-failure"})
	if err != nil {
		t.Fatal(err)
	}
	if first.OK || first.ExitCode != 9 {
		t.Fatalf("first response = %#v", first)
	}
	second, err := client.Exec("srv1", []string{"repeat-failure"})
	if err != nil {
		t.Fatal(err)
	}
	if second.OK || second.ExitCode != 9 || second.RunID == first.RunID {
		t.Fatalf("second response = %#v", second)
	}
	if got := jobs.starts.Load(); got != 2 {
		t.Fatalf("remote starts = %d, want 2", got)
	}
}

func TestJobForDoesNotResurrectPersistedDoneRun(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	command := "completed"
	old := newJob(command, "fingerprint")
	old.started = true
	old.startedAt = time.Now()
	old.done = true
	old.status = jobStatusDone
	registry := jobRegistry{Jobs: map[string]jobRecord{
		jobKey("srv1", command): newJobRecord("srv1", old),
	}}
	if err := saveJobRegistry(registry); err != nil {
		t.Fatal(err)
	}
	s := &server{
		entries: map[string]*entry{},
		jobs:    registry,
	}
	e := &entry{fingerprint: "fingerprint", jobs: map[string]*job{}}
	e.cond = sync.NewCond(&e.mu)
	s.entries["srv1"] = e

	got := s.jobFor(e, "srv1", command, "fingerprint")
	if got.id == old.id {
		t.Fatalf("persisted done run %s was resurrected", old.id)
	}
}

func TestBrokerRestartReattachesWithoutRerunningJob(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	t.Setenv("CORV_WAIT", "0s")
	resetBrokerTestHooks(t)

	jobs := newAsyncJobTestHandler(func(cmd string) (string, int) {
		return "start\nend\n", 0
	})
	jobs.rcAfter.Store(1000)
	sshServer := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer sshServer.cleanup()
	writeBrokerTestProfile(t, sshServer)

	errc := startBrokerProcessForTest(t, sshServer)
	client := NewClient("unused")
	resp, err := client.Exec("srv1", []string{"restart-safe"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Running || resp.Stdout != "start\nend\n" {
		t.Fatalf("first response = %#v", resp)
	}
	stopBrokerProcessForTest(t, errc)

	jobs.rcAfter.Store(jobs.rcCalls.Load() + 1)
	errc = startBrokerProcessForTest(t, sshServer)
	t.Cleanup(func() { stopBrokerProcessForTest(t, errc) })
	resp, err = client.Exec("srv1", []string{"restart-safe"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Running || !resp.OK || resp.Stdout != "" {
		t.Fatalf("reattach response = %#v", resp)
	}
	if got := jobs.starts.Load(); got != 1 {
		t.Fatalf("remote job started %d times, want 1", got)
	}
}

func TestBrokerDeltaDoesNotRepeatOrDropBytes(t *testing.T) {
	t.Setenv("CORV_WAIT", "0s")
	jobs := newAsyncJobTestHandler(func(cmd string) (string, int) {
		return "step1\nstep2\n", 0
	})
	jobs.rcAfter.Store(1000)
	server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer server.cleanup()
	startBrokerForTest(t, server)

	client := NewClient("unused")
	resp, err := client.Exec("srv1", []string{"delta-safe"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Running || resp.Stdout != "step1\nstep2\n" {
		t.Fatalf("first response = %#v", resp)
	}

	rec, ok := loadPersistedTestJob(t, "srv1", "delta-safe")
	if !ok {
		t.Fatal("persisted job not found")
	}
	if rec.Offset != int64(len("step1\nstep2\n")) {
		t.Fatalf("offset = %d, want %d", rec.Offset, len("step1\nstep2\n"))
	}

	jobs.rcAfter.Store(jobs.rcCalls.Load() + 1)
	resp, err = client.Exec("srv1", []string{"delta-safe"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Stdout != "" || !resp.OK {
		t.Fatalf("second response = %#v", resp)
	}
}

func TestBrokerDoneWithinWaitWindowKeepsOutput(t *testing.T) {
	t.Setenv("CORV_WAIT", "50ms")
	jobs := newAsyncJobTestHandler(func(cmd string) (string, int) {
		return "visible-before-rc\n", 0
	})
	jobs.rcAfter.Store(2)
	server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer server.cleanup()
	startBrokerForTest(t, server)

	resp, err := NewClient("unused").Exec("srv1", []string{"finishes-soon"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Running || !resp.OK || resp.Stdout != "visible-before-rc\n" {
		t.Fatalf("response = %#v", resp)
	}
}

func TestBrokerLargeDeltaAdvancesInBoundedChunks(t *testing.T) {
	t.Setenv("CORV_WAIT", "0s")
	payload := strings.Repeat("line of output\n", maxDeltaBytes/15*3)
	jobs := newAsyncJobTestHandler(func(string) (string, int) {
		return payload, 0
	})
	jobs.rcAfter.Store(1000)
	server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer server.cleanup()
	startBrokerForTest(t, server)

	client := NewClient("unused")
	if _, err := client.Exec("srv1", []string{"large-output"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exec("srv1", []string{"large-output"}); err != nil {
		t.Fatal(err)
	}

	jobs.mu.Lock()
	offsets := append([]int(nil), jobs.tailOffsets...)
	sizes := append([]int(nil), jobs.tailSizes...)
	jobs.mu.Unlock()
	if len(offsets) < 2 {
		t.Fatalf("tail polls = %d, want at least 2", len(offsets))
	}
	var emitted int64
	for i := range offsets {
		if sizes[i] <= 0 || sizes[i] > maxDeltaBytes {
			t.Fatalf("poll %d transferred %d bytes", i, sizes[i])
		}
		if want := int(emitted) + 1; offsets[i] != want {
			t.Fatalf("poll %d offset = %d, want %d", i, offsets[i], want)
		}
		emitted += int64(sizes[i])
	}

	rec, ok := loadPersistedTestJob(t, "srv1", "large-output")
	if !ok {
		t.Fatal("persisted job not found")
	}
	if rec.Offset != emitted {
		t.Fatalf("persisted offset = %d, emitted bytes = %d", rec.Offset, emitted)
	}
	if got := jobs.starts.Load(); got != 1 {
		t.Fatalf("remote job started %d times, want 1", got)
	}
}

func TestBrokerWatchStopsAtTotalDeltaLimit(t *testing.T) {
	t.Setenv("CORV_WAIT", "10s")
	payload := strings.Repeat("x", maxDeltaBytes*3)
	jobs := newAsyncJobTestHandler(func(string) (string, int) {
		return payload, 0
	})
	jobs.rcAfter.Store(1000)
	server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer server.cleanup()
	startBrokerForTest(t, server)

	started := time.Now()
	resp, err := NewClient("unused").Exec("srv1", []string{"unbounded-output"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Running {
		t.Fatalf("response = %#v", resp)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("bounded watch returned after %s", elapsed)
	}

	rec, ok := loadPersistedTestJob(t, "srv1", "unbounded-output")
	if !ok {
		t.Fatal("persisted job not found")
	}
	if rec.Offset != maxDeltaBytes {
		t.Fatalf("persisted offset = %d, want %d", rec.Offset, maxDeltaBytes)
	}
}

func TestBrokerStartsLargeCommandThroughStdin(t *testing.T) {
	t.Setenv("CORV_WAIT", "0s")
	script := strings.Repeat("printf x >/dev/null\n", 52*1024)
	jobs := newAsyncJobTestHandler(func(command string) (string, int) {
		if command != script {
			return "payload mismatch\n", 1
		}
		return "large command complete\n", 0
	})
	jobs.rcAfter.Store(1000)
	server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer server.cleanup()
	startBrokerForTest(t, server)

	client := NewClient("unused")
	first, err := client.Exec("srv1", []string{script})
	if err != nil {
		t.Fatal(err)
	}
	if !first.Running || first.RunID == "" {
		t.Fatalf("first response = %#v", first)
	}

	jobs.rcAfter.Store(jobs.rcCalls.Load())
	done, err := client.Exec("srv1", []string{script})
	if err != nil {
		t.Fatal(err)
	}
	if done.Running || !done.OK || done.RunID != first.RunID {
		t.Fatalf("completion response = %#v", done)
	}
	outputResp, err := client.Output(first.RunID, "")
	if err != nil {
		t.Fatal(err)
	}
	if !outputResp.OK || outputResp.Stdout != "large command complete\n" {
		t.Fatalf("output response = %#v", outputResp)
	}
	if got := jobs.starts.Load(); got != 1 {
		t.Fatalf("remote starts = %d, want 1", got)
	}
}

func TestBrokerLargeCompletedLogIsSavedTruncated(t *testing.T) {
	t.Setenv("CORV_WAIT", "0s")
	payload := strings.Repeat("x", maxLocalLogBytes+4096)
	jobs := newAsyncJobTestHandler(func(string) (string, int) {
		return payload, 0
	})
	server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer server.cleanup()
	startBrokerForTest(t, server)

	resp, err := NewClient("unused").Exec("srv1", []string{"large-completed-log"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Running || resp.ExitCode != 0 || !resp.OK {
		t.Fatalf("response = %#v", resp)
	}
	wantHighlight := fmt.Sprintf("Corv saved log was truncated at %d MiB", maxLocalLogBytes/(1024*1024))
	if !slices.Contains(resp.Highlights, wantHighlight) {
		t.Fatalf("highlights = %#v", resp.Highlights)
	}

	p, err := paths.Default()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(p.RunsDir, resp.RunID+".log"))
	if err != nil {
		t.Fatal(err)
	}
	marker := fmt.Sprintf("\n[Corv log truncated at %d MiB]\n", maxLocalLogBytes/(1024*1024))
	if len(data) != maxLocalLogBytes+len(marker) {
		t.Fatalf("saved log size = %d, want %d", len(data), maxLocalLogBytes+len(marker))
	}
	if !bytes.Equal(data[:maxLocalLogBytes], []byte(payload[:maxLocalLogBytes])) {
		t.Fatal("saved log prefix does not match remote output")
	}
	if string(data[maxLocalLogBytes:]) != marker {
		t.Fatalf("saved log marker = %q", data[maxLocalLogBytes:])
	}
}

func TestBrokerOutputReturnsPersistedRunOutcome(t *testing.T) {
	tests := []struct {
		name string
		code int
		ok   bool
	}{
		{name: "success", code: 0, ok: true},
		{name: "failure", code: 23, ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobs := newAsyncJobTestHandler(func(string) (string, int) {
				return "completed\n", tt.code
			})
			server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
			defer server.cleanup()
			startBrokerForTest(t, server)

			client := NewClient("unused")
			execResp, err := client.Exec("srv1", []string{"persist-outcome"})
			if err != nil {
				t.Fatal(err)
			}
			if execResp.Running || execResp.ExitCode != tt.code || execResp.OK != tt.ok {
				t.Fatalf("exec response = %#v", execResp)
			}

			outputResp, err := client.Output(execResp.RunID, "")
			if err != nil {
				t.Fatal(err)
			}
			if outputResp.ExitCode != tt.code || outputResp.OK != tt.ok {
				t.Fatalf("output response = %#v", outputResp)
			}
			if !outputResp.RunMetadata || outputResp.Connection != "srv1" || outputResp.Running {
				t.Fatalf("output metadata = %#v", outputResp)
			}
			if outputResp.StartedAt == nil || outputResp.FinishedAt == nil ||
				outputResp.FinishedAt.Before(*outputResp.StartedAt) {
				t.Fatalf("output timestamps = %#v", outputResp)
			}
		})
	}
}

func TestBrokerOutputFinalizesCompletedDetachedRun(t *testing.T) {
	t.Setenv("CORV_WAIT", "0s")
	jobs := newAsyncJobTestHandler(func(string) (string, int) {
		return "detached result\n", 17
	})
	jobs.rcAfter.Store(1000)
	server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer server.cleanup()
	startBrokerForTest(t, server)

	client := NewClient("unused")
	execResp, err := client.Exec("srv1", []string{"finish-via-output"})
	if err != nil {
		t.Fatal(err)
	}
	if !execResp.Running {
		t.Fatalf("exec response = %#v", execResp)
	}

	jobs.rcAfter.Store(jobs.rcCalls.Load())
	if _, err := client.Close("srv1"); err != nil {
		t.Fatal(err)
	}
	outputResp, err := client.Output(execResp.RunID, "")
	if err != nil {
		t.Fatal(err)
	}
	if outputResp.Running || outputResp.OK || outputResp.ExitCode != 17 {
		t.Fatalf("output response = %#v", outputResp)
	}
	if !outputResp.RunMetadata || outputResp.Connection != "srv1" ||
		outputResp.Stdout != "detached result\n" {
		t.Fatalf("output metadata = %#v", outputResp)
	}
	if got := jobs.starts.Load(); got != 1 {
		t.Fatalf("remote job starts = %d, want 1", got)
	}
}

func TestBrokerCompletedCommandReturnsFullOutputUpToBudget(t *testing.T) {
	t.Setenv("CORV_WAIT", "0s")
	var full strings.Builder
	full.WriteString("FIRST-LINE\n")
	for i := 0; i < 3000; i++ {
		full.WriteString("a line of moderately sized output to exceed the inline budget\n")
	}
	full.WriteString("LAST-LINE\n")
	want := full.String()
	if len(want) <= maxInlineOutputBytes {
		t.Fatalf("test setup: output %d bytes must exceed inline budget %d", len(want), maxInlineOutputBytes)
	}

	jobs := newAsyncJobTestHandler(func(string) (string, int) {
		return want, 0
	})
	jobs.rcAfter.Store(0)
	server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer server.cleanup()
	startBrokerForTest(t, server)

	client := NewClient("unused")
	execResp, err := client.Exec("srv1", []string{"verbose-command"})
	if err != nil {
		t.Fatal(err)
	}
	// The finished command returns inline output trimmed to the budget.
	if execResp.Running || !execResp.OK || execResp.ExitCode != 0 {
		t.Fatalf("exec response = %#v", execResp)
	}
	if !strings.Contains(execResp.Stdout, "line(s) hidden") {
		t.Fatal("expected a hidden-middle marker in inline output")
	}
	if !strings.Contains(execResp.Stdout, "FIRST-LINE") || !strings.Contains(execResp.Stdout, "LAST-LINE") {
		t.Fatal("inline output dropped the head or tail")
	}
	if len(execResp.Stdout) >= len(want) {
		t.Fatalf("inline output was not trimmed: %d bytes", len(execResp.Stdout))
	}

	// corv output returns the complete saved log.
	outputResp, err := client.Output(execResp.RunID, "")
	if err != nil {
		t.Fatal(err)
	}
	if outputResp.Stdout != want {
		t.Fatalf("corv output returned %d bytes, want full %d", len(outputResp.Stdout), len(want))
	}
}

func TestBrokerConcurrentOutputReturnsFullLog(t *testing.T) {
	t.Setenv("CORV_WAIT", "0s")
	jobs := newAsyncJobTestHandler(func(string) (string, int) {
		return "detached result\n", 17
	})
	jobs.rcAfter.Store(1000)
	server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer server.cleanup()
	startBrokerForTest(t, server)

	client := NewClient("unused")
	execResp, err := client.Exec("srv1", []string{"finish-concurrently"})
	if err != nil {
		t.Fatal(err)
	}
	if !execResp.Running {
		t.Fatalf("exec response = %#v", execResp)
	}

	// Mark the remote run done and drop the held connection so every
	// finalizer rebuilds the job from the persisted record - the path where
	// concurrent finalizers previously raced to overwrite the saved log.
	jobs.rcAfter.Store(jobs.rcCalls.Load())
	if _, err := client.Close("srv1"); err != nil {
		t.Fatal(err)
	}

	const n = 8
	var wg sync.WaitGroup
	resps := make([]Response, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resps[i], errs[i] = client.Output(execResp.RunID, "")
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("output %d error: %v", i, errs[i])
		}
		if resps[i].Running || resps[i].ExitCode != 17 || resps[i].Stdout != "detached result\n" {
			t.Fatalf("output %d response = %#v", i, resps[i])
		}
	}
}

func TestBrokerOutputReportsDistinctRunStates(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		t.Setenv("CORV_HOME", t.TempDir())
		s := &server{jobs: jobRegistry{Jobs: map[string]jobRecord{}}}
		resp := s.output(Request{RunID: "0000000000000000-aa"})
		if resp.Error != "unknown run id" || resp.Kind != "bad_request" {
			t.Fatalf("response = %#v", resp)
		}
	})

	t.Run("running", func(t *testing.T) {
		t.Setenv("CORV_WAIT", "0s")
		jobs := newAsyncJobTestHandler(func(string) (string, int) {
			return "pending\n", 0
		})
		jobs.rcAfter.Store(1000)
		server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
		defer server.cleanup()
		startBrokerForTest(t, server)

		client := NewClient("unused")
		execResp, err := client.Exec("srv1", []string{"still-running"})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Output(execResp.RunID, "")
		if err != nil {
			t.Fatal(err)
		}
		if !resp.Running || resp.ExitCode != 75 ||
			resp.Error != "run still in progress; re-run the command or corv output later" {
			t.Fatalf("response = %#v", resp)
		}
	})

	t.Run("expired", func(t *testing.T) {
		t.Setenv("CORV_WAIT", "0s")
		jobs := newAsyncJobTestHandler(func(string) (string, int) {
			return "lost\n", 0
		})
		jobs.rcAfter.Store(1000)
		server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
		defer server.cleanup()
		startBrokerForTest(t, server)

		client := NewClient("unused")
		execResp, err := client.Exec("srv1", []string{"expired-run"})
		if err != nil {
			t.Fatal(err)
		}
		jobs.mu.Lock()
		delete(jobs.logs, execResp.RunID)
		delete(jobs.rcs, execResp.RunID)
		jobs.mu.Unlock()
		if _, err := client.Close("srv1"); err != nil {
			t.Fatal(err)
		}
		resp, err := client.Output(execResp.RunID, "")
		if err != nil {
			t.Fatal(err)
		}
		if resp.Error != "run state expired before its log could be saved" {
			t.Fatalf("response = %#v", resp)
		}
	})
}

func TestBrokerOutputReadsLegacyLogWithoutMetadata(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	p, err := paths.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.RunsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	runID := "0000000000000000-aa"
	if err := os.WriteFile(filepath.Join(p.RunsDir, runID+".log"), []byte("legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	resp := (&server{}).output(Request{RunID: runID})
	if !resp.OK || resp.Stdout != "legacy\n" {
		t.Fatalf("legacy output response = %#v", resp)
	}
	if resp.RunMetadata || resp.StartedAt != nil || resp.FinishedAt != nil || resp.Connection != "" {
		t.Fatalf("legacy output fabricated metadata: %#v", resp)
	}
}

func TestBrokerLeavesRemoteLogWhenLocalSaveFails(t *testing.T) {
	t.Setenv("CORV_WAIT", "0s")
	jobs := newAsyncJobTestHandler(func(string) (string, int) {
		return "keep me\n", 0
	})
	jobs.rcAfter.Store(1000)
	server := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer server.cleanup()
	startBrokerForTest(t, server)

	client := NewClient("unused")
	first, err := client.Exec("srv1", []string{"save-failure"})
	if err != nil || !first.Running {
		t.Fatalf("first response = %#v, err = %v", first, err)
	}
	cleanupsBeforeCompletion := jobs.cleanups.Load()

	p, err := paths.Default()
	if err != nil {
		t.Fatal(err)
	}
	blockedLogPath := filepath.Join(p.RunsDir, first.RunID+".log")
	if err := os.MkdirAll(blockedLogPath, 0o700); err != nil {
		t.Fatal(err)
	}

	jobs.rcAfter.Store(jobs.rcCalls.Load() + 1)
	resp, err := client.Exec("srv1", []string{"save-failure"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Running || !resp.OK {
		t.Fatalf("completion response = %#v", resp)
	}
	if resp.RunID != first.RunID {
		t.Fatalf("completion run id = %s, want %s", resp.RunID, first.RunID)
	}
	if !slices.Contains(resp.Highlights, "Corv could not save the run log locally; remote copy retained") {
		t.Fatalf("highlights = %#v", resp.Highlights)
	}
	if got := jobs.cleanups.Load(); got != cleanupsBeforeCompletion {
		t.Fatalf("remote cleanup count changed from %d to %d after local save failure", cleanupsBeforeCompletion, got)
	}
	rec, ok := loadPersistedTestJob(t, "srv1", "save-failure")
	if !ok {
		t.Fatal("completed job was removed from jobs.json")
	}
	if rec.RunID != first.RunID || rec.Status != jobStatusDone {
		t.Fatalf("persisted job = %#v", rec)
	}

	if err := os.Remove(blockedLogPath); err != nil {
		t.Fatal(err)
	}
	retry, err := client.Exec("srv1", []string{"save-failure"})
	if err != nil {
		t.Fatal(err)
	}
	if retry.Running || !retry.OK || retry.RunID == first.RunID {
		t.Fatalf("retry response = %#v", retry)
	}
	if got := jobs.starts.Load(); got != 2 {
		t.Fatalf("remote job started %d times, want 2", got)
	}
	if _, err := os.Stat(filepath.Join(p.RunsDir, retry.RunID+".log")); err != nil {
		t.Fatalf("new run log missing after retry: %v", err)
	}
}

func TestSweepLocalRunsPreservesMetadata(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	p, err := paths.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.RunsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * jobTTL)
	files := map[string]bool{
		"jobs.json":       false,
		"old.log":         true,
		"old.meta.json":   true,
		"fresh.log":       false,
		"fresh.meta.json": false,
	}
	for name := range files {
		path := filepath.Join(p.RunsDir, name)
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(name, "fresh.") {
			if err := os.Chtimes(path, old, old); err != nil {
				t.Fatal(err)
			}
		}
	}

	(&server{}).sweepLocalRuns()

	for name, removed := range files {
		_, err := os.Stat(filepath.Join(p.RunsDir, name))
		switch {
		case removed && !os.IsNotExist(err):
			t.Fatalf("%s was not removed", name)
		case !removed && err != nil:
			t.Fatalf("%s should remain: %v", name, err)
		}
	}
}

func TestPersistedJobWithoutRemoteStateFailsWithoutRestart(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	t.Setenv("CORV_WAIT", "0s")
	resetBrokerTestHooks(t)

	jobs := newAsyncJobTestHandler(func(string) (string, int) {
		return "", 0
	})
	sshServer := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer sshServer.cleanup()
	writeBrokerTestProfile(t, sshServer)

	command := "never-started"
	j := newJob(command, "")
	j.started = true
	j.startedAt = time.Now()
	j.status = jobStatusStarting
	registry := jobRegistry{Jobs: map[string]jobRecord{
		jobKey("srv1", command): newJobRecord("srv1", j),
	}}
	if err := saveJobRegistry(registry); err != nil {
		t.Fatal(err)
	}

	errc := startBrokerProcessForTest(t, sshServer)
	t.Cleanup(func() { stopBrokerProcessForTest(t, errc) })
	resp, err := NewClient("unused").Exec("srv1", []string{command})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Running || resp.OK || !strings.Contains(resp.Error, "did not start") {
		t.Fatalf("response = %#v", resp)
	}
	if got := jobs.starts.Load(); got != 0 {
		t.Fatalf("remote job started %d times, want 0", got)
	}
}

func TestBrokerFailsFastWhenRemoteToolsAreMissing(t *testing.T) {
	var starts atomic.Int32
	server := startBrokerTestSSHServer(t, false, func(cmd string) (string, int) {
		if strings.Contains(cmd, "CORV_STARTED") {
			starts.Add(1)
			return "CORV_NO_POSIX\n", 127
		}
		return "", 0
	})
	defer server.cleanup()
	startBrokerForTest(t, server)

	resp, err := NewClient("unused").Exec("srv1", []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Running || resp.OK || !strings.Contains(resp.Error, "required POSIX tools") {
		t.Fatalf("response = %#v", resp)
	}
	if got := starts.Load(); got != 1 {
		t.Fatalf("start attempts = %d, want 1", got)
	}
}

func TestConcurrentColdStartSpawnsOneBroker(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	resetBrokerTestHooks(t)

	oldSpawnBroker := spawnBroker
	var spawns atomic.Int32
	errc := make(chan error, 1)
	spawnBroker = func(*Client) error {
		if spawns.Add(1) == 1 {
			go func() { errc <- Serve() }()
		}
		return nil
	}
	t.Cleanup(func() { spawnBroker = oldSpawnBroker })

	const clients = 12
	errs := make(chan error, clients)
	var wg sync.WaitGroup
	for range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := NewClient("unused").ensureRunning()
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := spawns.Load(); got != 1 {
		t.Fatalf("broker spawns = %d, want 1", got)
	}
	if err := NewClient("unused").Shutdown(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("broker did not stop")
	}
}

func TestClientReplacesStaleBroker(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	resetBrokerTestHooks(t)

	oldVersion := version.Version
	version.Version = "test-current"
	t.Cleanup(func() { version.Version = oldVersion })

	oldErrc := make(chan error, 1)
	go func() { oldErrc <- Serve() }()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(self)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := client.currentEndpoint(); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	ep, err := readEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	ep.Version = "stale"
	if err := writeEndpoint(ep); err != nil {
		t.Fatal(err)
	}

	oldSpawnBroker := spawnBroker
	var spawns atomic.Int32
	freshErrc := make(chan error, 1)
	spawnBroker = func(*Client) error {
		spawns.Add(1)
		go func() { freshErrc <- Serve() }()
		return nil
	}
	t.Cleanup(func() {
		spawnBroker = oldSpawnBroker
		_ = client.Shutdown()
		select {
		case err := <-freshErrc:
			if err != nil {
				t.Errorf("fresh broker: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("fresh broker did not stop")
		}
	})

	resp, err := client.request(Request{Op: OpPing})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatalf("response = %#v", resp)
	}
	if got := spawns.Load(); got != 1 {
		t.Fatalf("broker spawns = %d, want 1", got)
	}
	select {
	case err := <-oldErrc:
		if err != nil {
			t.Fatalf("stale broker: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stale broker did not receive shutdown")
	}
	if ep, ok := client.currentEndpoint(); !ok || ep.Version != version.Version {
		t.Fatalf("current endpoint = %#v, ok=%v", ep, ok)
	}
}

func TestSlowExecDoesNotBlockPingOrAnotherProfile(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	t.Setenv("CORV_WAIT", "500ms")
	resetBrokerTestHooks(t)

	jobs := newConcurrentJobTestHandler()
	sshServer := startBrokerTestSSHServerStdin(t, false, jobs.HandleStdin)
	defer sshServer.cleanup()
	writeBrokerTestProfiles(t, sshServer, "slow", "fast")
	errc := startBrokerProcessForTest(t, sshServer)
	t.Cleanup(func() { stopBrokerProcessForTest(t, errc) })

	slowDone := make(chan Response, 1)
	go func() {
		resp, _ := NewClient("unused").Exec("slow", []string{"slow"})
		slowDone <- resp
	}()
	select {
	case <-jobs.slowStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("slow command did not start")
	}

	start := time.Now()
	if !NewClient("unused").Running() {
		t.Fatal("broker ping failed during slow command")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("ping blocked for %s", elapsed)
	}

	start = time.Now()
	resp, err := NewClient("unused").Exec("fast", []string{"fast"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Stdout != "fast\n" {
		t.Fatalf("fast response = %#v", resp)
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("fast command blocked for %s", elapsed)
	}

	jobs.releaseSlow.Store(true)
	select {
	case <-slowDone:
	case <-time.After(2 * time.Second):
		t.Fatal("slow command did not finish")
	}
}

func TestEnrichJumpAuthFromSavedProfile(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	p, err := paths.Default()
	if err != nil {
		t.Fatal(err)
	}
	secrets := vault.New(p.VaultFile, p.VaultKey)
	if err := secrets.Set("profile:bastion", vault.Secret{Password: "jump-password", Passphrase: "jump-passphrase"}); err != nil {
		t.Fatal(err)
	}
	reg := profile.Registry{}
	if err := reg.Set(profile.Profile{
		Name:         "bastion",
		Target:       "ops@bastion.internal",
		Port:         2200,
		IdentityFile: "id_bastion",
		SecretRef:    "profile:bastion",
	}); err != nil {
		t.Fatal(err)
	}
	s := &server{secrets: secrets}
	jumps := []sshconn.JumpHost{{Host: "bastion"}}

	sshconn.EnrichJumpChain(jumps, reg, s.jumpSecret)

	if jumps[0].Host != "bastion.internal" || jumps[0].User != "ops" || jumps[0].Port != 2200 ||
		jumps[0].IdentityFile != "id_bastion" || jumps[0].Password != "jump-password" || jumps[0].Passphrase != "jump-passphrase" {
		t.Fatalf("jump not enriched: %#v", jumps[0])
	}
}

func startBrokerForTest(t *testing.T, server testSSHServer) {
	t.Helper()
	t.Setenv("CORV_HOME", t.TempDir())
	resetBrokerTestHooks(t)

	writeBrokerTestProfile(t, server)
	errc := startBrokerProcessForTest(t, server)
	t.Cleanup(func() { stopBrokerProcessForTest(t, errc) })
}

func resetBrokerTestHooks(t *testing.T) {
	t.Helper()
	oldOptions := testDialOptions
	testDialOptions = nil
	t.Cleanup(func() {
		testDialOptions = oldOptions
	})
}

func startBrokerTestSSHServer(t *testing.T, closeAfterExec bool, h func(string) (string, int)) testSSHServer {
	return startBrokerTestSSHServerStdin(t, closeAfterExec, func(command string, _ []byte) (string, int) {
		return h(command)
	})
}

func startBrokerTestSSHServerStdin(t *testing.T, closeAfterExec bool, h func(string, []byte) (string, int)) testSSHServer {
	t.Helper()

	hostSigner := newBrokerTestSigner(t)
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	server := testSSHServer{
		addr:    ln.Addr().String(),
		hostKey: hostSigner.PublicKey(),
		dials:   &atomic.Int32{},
		cleanup: func() { _ = ln.Close() },
	}
	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			server.dials.Add(1)
			go serveBrokerTestConn(nConn, cfg, closeAfterExec, h)
		}
	}()
	return server
}

func serveBrokerTestConn(nConn net.Conn, cfg *ssh.ServerConfig, closeAfterExec bool, h func(string, []byte) (string, int)) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, requests, err := newChan.Accept()
		if err != nil {
			return
		}
		done := make(chan struct{})
		closeConn := make(chan bool, 1)
		go func() {
			closeConn <- handleBrokerTestSession(ch, requests, h)
			close(done)
		}()
		if closeAfterExec {
			<-done
			if <-closeConn {
				_ = conn.Close()
				return
			}
		}
	}
}

func writeBrokerTestProfile(t *testing.T, server testSSHServer) {
	writeBrokerTestProfiles(t, server, "srv1")
}

func writeBrokerTestProfiles(t *testing.T, server testSSHServer, names ...string) {
	t.Helper()
	p, err := paths.Default()
	if err != nil {
		t.Fatal(err)
	}
	secrets := vault.New(p.VaultFile, p.VaultKey)
	store := profile.NewStore(p.ConfigFile, secrets)
	host, portText, err := net.SplitHostPort(server.addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		t.Fatal(err)
	}
	reg := profile.Registry{}
	for _, name := range names {
		if err := reg.Set(profile.Profile{Name: name, Target: "tester@" + host, Port: port}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Save(reg); err != nil {
		t.Fatal(err)
	}
}

func brokerTestProfile(t *testing.T, name string, server testSSHServer) profile.Profile {
	t.Helper()
	host, portText, err := net.SplitHostPort(server.addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		t.Fatal(err)
	}
	return profile.Profile{Name: name, Target: "tester@" + host, Port: port}
}

func startBrokerProcessForTest(t *testing.T, server testSSHServer) <-chan error {
	t.Helper()
	testDialOptions = func(profile.Profile) sshconn.DialOptions {
		return sshconn.DialOptions{
			HostKey: ssh.FixedHostKey(server.hostKey),
			Auth:    []ssh.AuthMethod{ssh.Password("x")},
		}
	}
	errc := make(chan error, 1)
	go func() { errc <- Serve() }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if NewClient("unused").Running() {
			return errc
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("broker did not start")
	return errc
}

func stopBrokerProcessForTest(t *testing.T, errc <-chan error) {
	t.Helper()
	_ = NewClient("unused").Shutdown()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("broker Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("broker did not stop")
	}
}

// dropExitSentinel lets a test handler simulate a connection that drops after
// the command has started but before the exit status is sent.
const dropExitSentinel = -1

func handleBrokerTestSession(ch ssh.Channel, requests <-chan *ssh.Request, h func(string, []byte) (string, int)) bool {
	defer ch.Close()
	for req := range requests {
		switch req.Type {
		case "exec":
			cmd := string(req.Payload[4:])
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			var stdin []byte
			if strings.Contains(cmd, `cat > "$dir/`) {
				stdin, _ = io.ReadAll(ch)
			}
			out, code := h(cmd, stdin)
			_, _ = io.WriteString(ch, out)
			if code == dropExitSentinel {
				return false
			}
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
			return strings.Contains(cmd, "rm -f \"$dir/")
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
	return false
}

func TestBrokerDoesNotRerunStartedCommand(t *testing.T) {
	var execs atomic.Int32
	server := startBrokerTestSSHServer(t, false, func(cmd string) (string, int) {
		if strings.Contains(cmd, "CORV_STARTED") {
			execs.Add(1)
			return "side effect\n", dropExitSentinel
		}
		if strings.Contains(cmd, "printf done") && strings.Contains(cmd, "printf missing") {
			return "missing", 0
		}
		return "", 0
	})
	defer server.cleanup()
	startBrokerForTest(t, server)

	client := NewClient("unused")
	resp, err := client.Exec("srv1", []string{"restart-db"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Running || resp.ExitCode != 75 {
		t.Fatalf("uncertain start response = %#v", resp)
	}
	resp, err = client.Exec("srv1", []string{"restart-db"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Running || resp.OK || resp.Kind != string(sshconn.ErrSSH) {
		t.Fatalf("reattach response = %#v", resp)
	}
	if got := execs.Load(); got != 1 {
		t.Fatalf("command executed %d times; a started command must not be re-run", got)
	}
}

func TestBrokerStartTimeoutIsUncertainAndNeverRetried(t *testing.T) {
	t.Setenv("CORV_WAIT", "0s")
	oldTimeout := controlOpTimeout
	controlOpTimeout = 50 * time.Millisecond
	t.Cleanup(func() { controlOpTimeout = oldTimeout })

	var starts atomic.Int32
	server := startBrokerTestSSHServer(t, false, func(cmd string) (string, int) {
		if strings.Contains(cmd, "CORV_STARTED") {
			starts.Add(1)
			time.Sleep(200 * time.Millisecond)
			return "CORV_STARTED\n", 0
		}
		if strings.Contains(cmd, "printf done") && strings.Contains(cmd, "printf missing") {
			return "missing", 0
		}
		return "", 0
	})
	defer server.cleanup()
	startBrokerForTest(t, server)

	started := time.Now()
	client := NewClient("unused")
	resp, err := client.Exec("srv1", []string{"deploy-once"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Running || resp.RunID == "" {
		t.Fatalf("timeout response = %#v", resp)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("start timeout returned after %s", elapsed)
	}

	time.Sleep(250 * time.Millisecond)
	resp, err = client.Exec("srv1", []string{"deploy-once"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Running || resp.OK || !strings.Contains(resp.Error, "did not start") {
		t.Fatalf("reattach response = %#v", resp)
	}
	if got := starts.Load(); got != 1 {
		t.Fatalf("remote start attempts = %d, want 1", got)
	}
}

type asyncJobTestHandler struct {
	mu          sync.Mutex
	starts      atomic.Int32
	cleanups    atomic.Int32
	rcAfter     atomic.Int32
	rcCalls     atomic.Int32
	logs        map[string]string
	rcs         map[string]int
	tailOffsets []int
	tailSizes   []int
	runFunc     func(string) (string, int)
}

func newAsyncJobTestHandler(run func(string) (string, int)) *asyncJobTestHandler {
	h := &asyncJobTestHandler{
		logs: map[string]string{},
		rcs:  map[string]int{},
	}
	h.rcAfter.Store(1)
	h.runFunc = run
	return h
}

func (h *asyncJobTestHandler) HandleStdin(cmd string, stdin []byte) (string, int) {
	switch {
	case strings.Contains(cmd, "CORV_STARTED"):
		h.starts.Add(1)
		id := parseJobID(cmd)
		userCommand := string(stdin)
		out, code := h.runFunc(userCommand)
		h.mu.Lock()
		h.logs[id] = out
		h.rcs[id] = code
		h.mu.Unlock()
		return "CORV_STARTED\n", 0
	case strings.Contains(cmd, "printf done") && strings.Contains(cmd, "printf missing"):
		id := parseJobID(cmd)
		h.mu.Lock()
		_, hasLog := h.logs[id]
		_, hasRC := h.rcs[id]
		h.mu.Unlock()
		if hasRC && h.rcCalls.Load() >= h.rcAfter.Load() {
			return "done", 0
		}
		if hasLog {
			return "running", 0
		}
		return "missing", 0
	case strings.Contains(cmd, "tail -c +"):
		id := parseJobID(cmd)
		offset := parseTailOffset(cmd)
		h.mu.Lock()
		log := h.logs[id]
		h.mu.Unlock()
		if offset > len(log) {
			return "", 0
		}
		out := log[offset-1:]
		if limit := parseHeadLimit(cmd); limit > 0 && len(out) > limit {
			out = out[:limit]
		}
		h.mu.Lock()
		h.tailOffsets = append(h.tailOffsets, offset)
		h.tailSizes = append(h.tailSizes, len(out))
		h.mu.Unlock()
		return out, 0
	case strings.Contains(cmd, ".rc") && strings.Contains(cmd, "cat"):
		id := parseJobID(cmd)
		if h.rcCalls.Add(1) < h.rcAfter.Load() {
			return "", 0
		}
		h.mu.Lock()
		code := h.rcs[id]
		h.mu.Unlock()
		return fmt.Sprintf("%d\n", code), 0
	case strings.Contains(cmd, ".log") && strings.Contains(cmd, "cat"):
		h.mu.Lock()
		log := h.logs[parseJobID(cmd)]
		h.mu.Unlock()
		if len(log) > maxLocalLogBytes+1 {
			log = log[:maxLocalLogBytes+1]
		}
		return log, 0
	case strings.Contains(cmd, "rm -f"):
		id := parseJobID(cmd)
		h.cleanups.Add(1)
		h.mu.Lock()
		delete(h.logs, id)
		delete(h.rcs, id)
		h.mu.Unlock()
		return "", 0
	default:
		return "unexpected " + cmd + "\n", 1
	}
}

type concurrentJobTestHandler struct {
	mu          sync.Mutex
	logs        map[string]string
	commands    map[string]string
	slowStarted chan struct{}
	startOnce   sync.Once
	releaseSlow atomic.Bool
}

func newConcurrentJobTestHandler() *concurrentJobTestHandler {
	return &concurrentJobTestHandler{
		logs:        map[string]string{},
		commands:    map[string]string{},
		slowStarted: make(chan struct{}),
	}
}

func (h *concurrentJobTestHandler) HandleStdin(cmd string, stdin []byte) (string, int) {
	switch {
	case strings.Contains(cmd, "CORV_STARTED"):
		id := parseJobID(cmd)
		command := string(stdin)
		output := command + "\n"
		h.mu.Lock()
		h.logs[id] = output
		h.commands[id] = command
		h.mu.Unlock()
		if command == "slow" {
			h.startOnce.Do(func() { close(h.slowStarted) })
		}
		return "CORV_STARTED\n", 0
	case strings.Contains(cmd, "printf done") && strings.Contains(cmd, "printf missing"):
		id := parseJobID(cmd)
		h.mu.Lock()
		command, ok := h.commands[id]
		h.mu.Unlock()
		if !ok {
			return "missing", 0
		}
		if command == "slow" && !h.releaseSlow.Load() {
			return "running", 0
		}
		return "done", 0
	case strings.Contains(cmd, "tail -c +"):
		id := parseJobID(cmd)
		offset := parseTailOffset(cmd)
		h.mu.Lock()
		log := h.logs[id]
		h.mu.Unlock()
		if offset > len(log) {
			return "", 0
		}
		out := log[offset-1:]
		if limit := parseHeadLimit(cmd); limit > 0 && len(out) > limit {
			out = out[:limit]
		}
		return out, 0
	case strings.Contains(cmd, ".rc") && strings.Contains(cmd, "cat"):
		id := parseJobID(cmd)
		h.mu.Lock()
		command := h.commands[id]
		h.mu.Unlock()
		if command == "slow" && !h.releaseSlow.Load() {
			return "", 0
		}
		return "0\n", 0
	case strings.Contains(cmd, ".log") && strings.Contains(cmd, "cat"):
		h.mu.Lock()
		log := h.logs[parseJobID(cmd)]
		h.mu.Unlock()
		return log, 0
	case strings.Contains(cmd, "rm -f"):
		return "", 0
	default:
		return "", 0
	}
}

var (
	jobIDRE    = regexp.MustCompile(`(?:/corv-jobs[^/]*/|\$dir/)([a-f0-9-]+)\.`)
	tailOffset = regexp.MustCompile(`tail -c \+([0-9]+)`)
	headLimit  = regexp.MustCompile(`head -c ([0-9]+)`)
)

func parseJobID(cmd string) string {
	m := jobIDRE.FindStringSubmatch(cmd)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

func parseTailOffset(cmd string) int {
	m := tailOffset.FindStringSubmatch(cmd)
	if len(m) != 2 {
		return 1
	}
	var n int
	_, _ = fmt.Sscanf(m[1], "%d", &n)
	return n
}

func parseHeadLimit(cmd string) int {
	m := headLimit.FindStringSubmatch(cmd)
	if len(m) != 2 {
		return 0
	}
	var limit int
	_, _ = fmt.Sscanf(m[1], "%d", &limit)
	return limit
}

func loadPersistedTestJob(t *testing.T, profileName, command string) (jobRecord, bool) {
	t.Helper()
	reg, err := loadJobRegistry()
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := reg.Jobs[jobKey(profileName, command)]
	return rec, ok
}

func newBrokerTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
