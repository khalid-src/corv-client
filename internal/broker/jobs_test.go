package broker

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestStartJobCommandReadsScriptFromStdin(t *testing.T) {
	cmd := startJobCommand("abc123")
	if !strings.Contains(cmd, `cat > "$dir/abc123.sh"`) || !strings.Contains(cmd, "CORV_STARTED") {
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
	cmd := startJobCommand("abc123")
	for _, want := range []string{
		"for tool in id tail head wc mkdir chmod cat rm sh",
		`command -v "$tool"`,
		"command -v setsid",
		"command -v nohup",
		"CORV_NO_POSIX",
	} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("start command missing %q: %s", want, cmd)
		}
	}
}

func TestRemoteJobCommandsUsePrivatePerUserDirectory(t *testing.T) {
	commands := []string{
		startJobCommand("abc123"),
		tailJobCommand("abc123", 0, maxDeltaBytes),
		stateJobCommand("abc123"),
		rcJobCommand("abc123"),
		fullLogCommand("abc123"),
		cleanupJobCommand("abc123"),
		sweepRemoteCommand(),
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

func TestFullLogCommandRetainsHeadAndTailWithinTransferLimit(t *testing.T) {
	got := fullLogCommand("abc123")
	for _, want := range []string{
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
	cmd := sweepRemoteCommand()
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
