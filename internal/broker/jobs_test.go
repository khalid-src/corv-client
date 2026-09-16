package broker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/khalid-src/corv-client/internal/paths"
)

func fixedRetentionTime() time.Time {
	return time.Date(2040, 3, 15, 12, 0, 0, 0, time.UTC)
}

func TestStartJobCommandReadsScriptFromStdin(t *testing.T) {
	cmd := startJobCommand("abc123", 0)
	if !strings.Contains(cmd, `cat > "$upload"`) || !strings.Contains(cmd, `mv "$upload" "$script"`) || !strings.Contains(cmd, "CORV_STARTED") {
		t.Fatalf("start command missing expected plumbing: %s", cmd)
	}
	if strings.Contains(cmd, "base64") || len(cmd) > 2048 {
		t.Fatalf("start command contains an inline payload: %s", cmd)
	}
}

func TestTailJobCommandUsesNextByteOffset(t *testing.T) {
	if got := tailJobCommand("abc123", 0, maxDeltaBytes); !strings.Contains(got, "tail -c +1") ||
		!strings.Contains(got, "head -c 524288") {
		t.Fatalf("offset 0 command = %s", got)
	}
	if got := tailJobCommand("abc123", 41, 1024); !strings.Contains(got, "tail -c +42") ||
		!strings.Contains(got, "head -c 1024") {
		t.Fatalf("offset 41 command = %s", got)
	}
}

func TestStartJobCommandChecksRemoteToolsAndFallsBackToNohup(t *testing.T) {
	cmd := startJobCommand("abc123", 0)
	for _, want := range []string{
		"for tool in id tail head wc mkdir chmod cat rm mv sh date",
		`command -v "$tool"`,
		"command -v setsid",
		"command -v nohup",
		"CORV_RC_V2",
		"CORV_UPLOAD_INCOMPLETE",
		`wc -c < "$upload"`,
		`mv "$2.tmp" "$2"`,
		"CORV_NO_POSIX",
	} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("start command missing %q: %s", want, cmd)
		}
	}
}

func TestParseRemoteExitSupportsLegacyAndTimedRecords(t *testing.T) {
	legacy, err := parseRemoteExit("17\n")
	if err != nil {
		t.Fatal(err)
	}
	if legacy.code != 17 || !legacy.finishedAt.IsZero() || legacy.duration != 0 {
		t.Fatalf("legacy exit = %#v", legacy)
	}

	finished := time.Date(2026, 8, 10, 12, 30, 0, 0, time.UTC)
	timed, err := parseRemoteExit(fmt.Sprintf("CORV_RC_V2 23 %d 91\n", finished.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if timed.code != 23 || !timed.finishedAt.Equal(finished) || timed.duration != 91*time.Second {
		t.Fatalf("timed exit = %#v", timed)
	}

	for _, raw := range []string{"invalid", "CORV_RC_V2 0 nope 1", "CORV_RC_V2 0 1 -1"} {
		if _, err := parseRemoteExit(raw); err == nil {
			t.Fatalf("accepted invalid remote exit %q", raw)
		}
	}
}

func TestResolveRemoteTimingUsesExecutionDuration(t *testing.T) {
	started := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	observed := started.Add(10 * time.Minute)
	finished, duration := resolveRemoteTiming(started, observed, remoteExit{
		finishedAt: observed,
		duration:   90 * time.Second,
	})
	if !finished.Equal(observed) || duration != 90*time.Second {
		t.Fatalf("finished=%s duration=%s", finished, duration)
	}
}

func TestResolveRemoteTimingBoundsClockSkew(t *testing.T) {
	started := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	observed := started.Add(2 * time.Minute)
	finished, duration := resolveRemoteTiming(started, observed, remoteExit{
		finishedAt: observed.Add(time.Hour),
		duration:   30 * time.Second,
	})
	if !finished.Equal(observed) || duration != 30*time.Second {
		t.Fatalf("finished=%s duration=%s", finished, duration)
	}
}

func TestRemoteJobCommandsUsePrivatePerUserDirectory(t *testing.T) {
	commands := []string{
		startJobCommand("abc123", 0),
		tailJobCommand("abc123", 0, maxDeltaBytes),
		stateJobCommand("abc123"),
		progressJobCommand("abc123"),
		rcJobCommand("abc123"),
		fullLogCommand("abc123"),
		cleanupJobCommand("abc123"),
		sweepRemoteCommand(fixedRetentionTime()),
	}
	for _, cmd := range commands {
		if !strings.Contains(cmd, "corv-jobs-$(id -u)") {
			t.Fatalf("command does not use the per-user job directory: %s", cmd)
		}
	}
	start := commands[0]
	if !strings.Contains(start, "umask 077") || !strings.Contains(start, "chmod 700") {
		t.Fatalf("start command does not protect remote state: %s", start)
	}
}

func TestParseJobProgressBoundsAndReportsOriginalSize(t *testing.T) {
	raw := []byte("CORV_PROGRESS_V1 running 20000\nrecent output\n")
	got, err := parseJobProgress(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.state != "running" || got.originalBytes != 20000 || string(got.data) != "recent output\n" {
		t.Fatalf("progress = %#v", got)
	}
	cmd := progressJobCommand("abc123")
	if !strings.Contains(cmd, fmt.Sprintf("tail -c %d", maxRunningOutputBytes)) ||
		!strings.Contains(cmd, "CORV_PROGRESS_V1") {
		t.Fatalf("progress command is not bounded: %s", cmd)
	}
}

func TestParseJobProgressRejectsMalformedFrame(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte("missing header\n"),
		[]byte("CORV_PROGRESS_V1 invalid 1\nx"),
		[]byte("CORV_PROGRESS_V1 running nope\nx"),
		append([]byte("CORV_PROGRESS_V1 running 1\n"), bytes.Repeat([]byte("x"), maxRunningOutputBytes+1)...),
	} {
		if _, err := parseJobProgress(raw); err == nil {
			t.Fatalf("accepted malformed frame %q", raw[:min(len(raw), 80)])
		}
	}
}

func TestFullLogCommandRetainsHeadAndTailWithinTransferLimit(t *testing.T) {
	got := fullLogCommand("abc123")
	for _, want := range []string{
		"CORV_LOG_MISSING",
		"wc -c",
		fmt.Sprintf("head -c %d", retainedLogHeadBytes),
		fmt.Sprintf("tail -c %d", retainedLogTailBytes),
		"CORV_LOG_V1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("full log command = %s, want %q", got, want)
		}
	}
	if retainedLogHeadBytes+retainedLogTailBytes+retainedLogFrameMargin > maxLocalLogBytes {
		t.Fatal("retained log payload exceeds the local limit")
	}
}

func TestParseRetainedLogPreservesSmallLog(t *testing.T) {
	raw := []byte("CORV_LOG_V1 12 12 0\nhello world\n")
	got, err := parseRetainedLog(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.data) != "hello world\n" || got.originalBytes != 12 || got.truncated {
		t.Fatalf("retained log = %#v", got)
	}
}

func TestParseRetainedLogDistinguishesMissingFromEmpty(t *testing.T) {
	missing, err := parseRetainedLog([]byte("CORV_LOG_MISSING\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !missing.missing {
		t.Fatalf("missing log = %#v", missing)
	}
	empty, err := parseRetainedLog([]byte("CORV_LOG_V1 0 0 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if empty.missing || len(empty.data) != 0 {
		t.Fatalf("empty log = %#v", empty)
	}
}

func TestParseRetainedLogPreservesLargeLogTail(t *testing.T) {
	head := bytes.Repeat([]byte("h"), retainedLogHeadBytes)
	tail := bytes.Repeat([]byte("t"), retainedLogTailBytes)
	originalBytes := int64(maxLocalLogBytes + 4096)
	raw := []byte(fmt.Sprintf("CORV_LOG_V1 %d %d %d\n", originalBytes, len(head), len(tail)))
	raw = append(raw, head...)
	raw = append(raw, tail...)

	got, err := parseRetainedLog(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.truncated || got.originalBytes != originalBytes {
		t.Fatalf("retained log = %#v", got)
	}
	if len(got.data) > maxLocalLogBytes {
		t.Fatalf("saved bytes = %d, limit %d", len(got.data), maxLocalLogBytes)
	}
	if !bytes.HasPrefix(got.data, head) || !bytes.HasSuffix(got.data, tail) {
		t.Fatal("retained log lost its head or tail")
	}
	if !bytes.Contains(got.data, []byte("bytes omitted")) {
		t.Fatal("retained log has no omission marker")
	}
}

func TestOutputMarksInvalidUTF8AsLossy(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	p, err := paths.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.RunsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	runID := "0000000000000000-aabb"
	if err := os.WriteFile(filepath.Join(p.RunsDir, runID+".log"), []byte{'o', 'k', '\n', 0xff, '\n'}, 0o600); err != nil {
		t.Fatal(err)
	}
	resp := (&server{}).output(Request{RunID: runID})
	if !resp.OK || !resp.Lossy || !strings.Contains(resp.Stdout, "\uFFFD") {
		t.Fatalf("response = %#v", resp)
	}
}

func TestWaitAndIPCTimeoutsAreBounded(t *testing.T) {
	t.Setenv("CORV_WAIT", "24h")
	if got := waitWindow(); got != maxWait {
		t.Fatalf("wait window = %s, want %s", got, maxWait)
	}
	if got := roundTripTimeout(Request{Op: OpExec}); got > 5*time.Minute || got <= maxWait {
		t.Fatalf("exec round-trip timeout = %s", got)
	}
	if got := roundTripTimeout(Request{Op: OpOutput}); got <= controlOpTimeout {
		t.Fatalf("output round-trip timeout = %s", got)
	}
	if got := roundTripTimeout(Request{Op: OpPing}); got != 30*time.Second {
		t.Fatalf("ping round-trip timeout = %s", got)
	}
}

func TestWaitWindowAcceptsBareSeconds(t *testing.T) {
	t.Setenv("CORV_WAIT", "1")
	if got := waitWindow(); got != time.Second {
		t.Fatalf("wait window = %s, want 1s", got)
	}
}

func TestParseWaitPerInvocation(t *testing.T) {
	fallback := 42 * time.Second
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"", fallback},
		{"  ", fallback},
		{"0", 0},
		{"500ms", 500 * time.Millisecond},
		{"3", 3 * time.Second},
		{"2m", 2 * time.Minute},
		{"24h", maxWait},
		{"nonsense", fallback},
		{"-5s", fallback},
	}
	for _, c := range cases {
		if got := parseWait(c.raw, fallback); got != c.want {
			t.Fatalf("parseWait(%q) = %s, want %s", c.raw, got, c.want)
		}
	}
}

func TestRemoteSweepRequiresTerminalExitStatus(t *testing.T) {
	cmd := sweepRemoteCommand(fixedRetentionTime())
	for _, want := range []string{
		`for rc in "$dir"/*.rc`,
		`[ -s "$rc" ] || continue`,
		`rm -f "$dir/$stem.sh" "$dir/$stem.log" "$dir/$stem.rc"`,
	} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("sweep command missing %q: %s", want, cmd)
		}
	}
	if strings.Contains(cmd, "-mtime") {
		t.Fatalf("sweep command uses log age as liveness: %s", cmd)
	}
}

func TestListRunsCombinesActiveAndRetainedWithoutTargets(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	p, err := paths.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.RunsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := fixedRetentionTime()
	started := now.Add(-2 * time.Hour)
	finished := started.Add(time.Minute)
	meta := runMetadata{Connection: "done-host", StartedAt: started, FinishedAt: finished, ExitCode: 9}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	doneID := "0000000000000001-aabb"
	if err := os.WriteFile(filepath.Join(p.RunsDir, doneID+".meta.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	activeID := "0000000000000002-aabb"
	s := &server{now: func() time.Time { return now }, jobs: jobRegistry{Jobs: map[string]jobRecord{
		"active": {
			RunID: activeID, Profile: "active-host", Status: jobStatusRunning,
			StartedAt: started.Add(time.Hour).Unix(),
		},
	}}}
	runs, err := s.listRuns()
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0].RunID != activeID || !runs[0].Running || runs[0].Connection != "active-host" {
		t.Fatalf("runs = %#v", runs)
	}
	if runs[0].ExitCode == nil || *runs[0].ExitCode != 75 {
		t.Fatalf("active exit code = %v, want 75", runs[0].ExitCode)
	}
	if runs[1].RunID != doneID || runs[1].Running || runs[1].ExitCode == nil || *runs[1].ExitCode != 9 || runs[1].Connection != "done-host" {
		t.Fatalf("runs = %#v", runs)
	}
}

func TestListRunsMarksOldUnverifiedRunUnknown(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	now := fixedRetentionTime()
	started := now.Add(-2 * jobTTL)
	s := &server{now: func() time.Time { return now }, jobs: jobRegistry{Jobs: map[string]jobRecord{
		"stale": {
			RunID: "0000000000000002-aabb", Profile: "stale-host",
			Status: jobStatusRunning, StartedAt: started.Unix(),
		},
	}}}

	runs, err := s.listRuns()
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Status != jobStatusUnknown || runs[0].Running || runs[0].ExitCode != nil {
		t.Fatalf("runs = %#v", runs)
	}
}

func TestListRunsDoesNotReportCompletionTimeForExpiredRun(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	now := fixedRetentionTime()
	s := &server{now: func() time.Time { return now }, jobs: jobRegistry{Jobs: map[string]jobRecord{
		"expired": {
			RunID: "0000000000000004-aabb", Profile: "expired-host",
			Status: jobStatusExpired, StartedAt: now.Add(-time.Hour).Unix(), FinishedAt: now.UnixNano(),
		},
	}}}

	runs, err := s.listRuns()
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Status != jobStatusExpired || runs[0].FinishedAt != nil || runs[0].ExitCode != nil {
		t.Fatalf("runs = %#v", runs)
	}
}

func TestOutputClassifiesLocalFailures(t *testing.T) {
	t.Run("invalid run id", func(t *testing.T) {
		resp := (&server{}).output(Request{RunID: "invalid"})
		if resp.Kind != "bad_request" {
			t.Fatalf("response = %#v", resp)
		}
	})

	t.Run("invalid metadata", func(t *testing.T) {
		t.Setenv("CORV_HOME", t.TempDir())
		p, err := paths.Default()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(p.RunsDir, 0o700); err != nil {
			t.Fatal(err)
		}
		runID := "0000000000000005-aabb"
		if err := os.WriteFile(filepath.Join(p.RunsDir, runID+".log"), []byte("done\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p.RunsDir, runID+".meta.json"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		resp := (&server{}).output(Request{RunID: runID})
		if resp.Kind != "local_error" {
			t.Fatalf("response = %#v", resp)
		}
	})
}

func TestListRunsKeepsRecentlyObservedOldRunRunning(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	now := fixedRetentionTime()
	started := now.Add(-2 * jobTTL)
	seen := now.Add(-time.Minute)
	s := &server{now: func() time.Time { return now }, jobs: jobRegistry{Jobs: map[string]jobRecord{
		"active": {
			RunID: "0000000000000003-aabb", Profile: "active-host",
			Status: jobStatusRunning, StartedAt: started.Unix(), LastSeenAt: seen.UnixNano(),
		},
	}}}

	runs, err := s.listRuns()
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Status != jobStatusRunning || !runs[0].Running ||
		runs[0].ExitCode == nil || *runs[0].ExitCode != 75 {
		t.Fatalf("runs = %#v", runs)
	}
}
