package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/khalid-src/corv-client/internal/broker"
)

func withHome(t *testing.T) {
	t.Helper()
	t.Setenv("CORV_HOME", t.TempDir())
}

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func TestDoctorDefaultIsPrivacySafe(t *testing.T) {
	withHome(t)
	if code, _, errOut := runCLI("add", "srv1", "deploy@192.168.1.5", "--port", "2222"); code != 0 {
		t.Fatalf("add failed: code=%d stderr=%q", code, errOut)
	}

	code, out, errOut := runCLI("doctor", "srv1")
	if code != 0 {
		t.Fatalf("doctor failed: code=%d stderr=%q", code, errOut)
	}
	for _, private := range []string{"@", "192.168.1.5", "2222", "config.json", "audit.jsonl"} {
		if strings.Contains(out, private) {
			t.Fatalf("doctor default leaked %q:\n%s", private, out)
		}
	}
	if !strings.Contains(out, "connection:       srv1") {
		t.Fatalf("doctor default missing connection name:\n%s", out)
	}
}

func TestUnknownConnectionJSON(t *testing.T) {
	withHome(t)

	code, out, errOut := runCLI("missing", "--json", "--", "true")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d stdout=%q stderr=%q", code, out, errOut)
	}
	if errOut != "" {
		t.Fatalf("expected no plain stderr for json error, got %q", errOut)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out)
	}
	if got["connection"] != "missing" || got["ok"] != false || got["error_kind"] != "unknown_connection" {
		t.Fatalf("unexpected json: %#v", got)
	}
	if got["stdout"] != "" || got["run_id"] != "" || got["running"] != false {
		t.Fatalf("unexpected json fields: %#v", got)
	}
	if highlights, ok := got["highlights"].([]any); !ok || len(highlights) != 0 {
		t.Fatalf("expected empty highlights array, got %#v", got["highlights"])
	}
}

func TestParseOutputArgsJSON(t *testing.T) {
	asJSON, runID, pattern, err := parseOutputArgs([]string{"--json", "abc123", "needle"})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !asJSON || runID != "abc123" || pattern != "needle" {
		t.Fatalf("unexpected parse: asJSON=%v runID=%q pattern=%q", asJSON, runID, pattern)
	}
}

func TestOutputJSONUsesPersistedFields(t *testing.T) {
	var out bytes.Buffer
	code := writeOutputJSON(&out, broker.Response{
		OK:     true,
		RunID:  "run-123",
		Stdout: "done\n",
	})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out.String())
	}
	if got["run_id"] != "run-123" || got["stdout"] != "done\n" || got["ok"] != true {
		t.Fatalf("unexpected json: %#v", got)
	}
	if highlights, ok := got["highlights"].([]any); !ok || len(highlights) != 0 {
		t.Fatalf("expected empty highlights array, got %#v", got["highlights"])
	}
	for _, fabricated := range []string{"connection", "exit_code", "running", "started_at"} {
		if _, ok := got[fabricated]; ok {
			t.Fatalf("output json fabricated %q: %#v", fabricated, got)
		}
	}
}

func TestOutputJSONIncludesPersistedRunOutcome(t *testing.T) {
	startedAt := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Minute)
	var out bytes.Buffer
	code := writeOutputJSON(&out, broker.Response{
		OK:          false,
		ExitCode:    23,
		RunID:       "run-123",
		Stdout:      "failed\n",
		Connection:  "srv1",
		StartedAt:   &startedAt,
		FinishedAt:  &finishedAt,
		Truncated:   true,
		RunMetadata: true,
	})
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out.String())
	}
	if got["ok"] != false || got["exit_code"] != float64(23) || got["connection"] != "srv1" {
		t.Fatalf("unexpected outcome json: %#v", got)
	}
	if got["running"] != false || got["truncated"] != true {
		t.Fatalf("unexpected state json: %#v", got)
	}
	if got["started_at"] != startedAt.Format(time.RFC3339) ||
		got["finished_at"] != finishedAt.Format(time.RFC3339) {
		t.Fatalf("unexpected timestamps: %#v", got)
	}
}

func TestOutputJSONIncludesErrorKind(t *testing.T) {
	var out bytes.Buffer
	writeOutputJSON(&out, broker.Response{
		OK:    false,
		RunID: "0000000000000000-aa",
		Error: "unknown run id",
		Kind:  "bad_request",
	})
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["error_kind"] != "bad_request" {
		t.Fatalf("json = %#v", got)
	}
}

func TestAddRejectsReservedName(t *testing.T) {
	withHome(t)
	code, _, errOut := runCLI("add", "log", "user@host")
	if code == 0 {
		t.Fatal("expected add to reject the reserved name 'log'")
	}
	if !strings.Contains(errOut, "reserved") {
		t.Fatalf("expected reserved-name error, got %q", errOut)
	}
}

func TestLogClearRejectsName(t *testing.T) {
	withHome(t)
	code, _, errOut := runCLI("log", "srv1", "--clear")
	if code == 0 {
		t.Fatal("expected --clear with a name to be rejected")
	}
	if !strings.Contains(errOut, "whole audit log") {
		t.Fatalf("expected clear-scope error, got %q", errOut)
	}
}

func TestDoctorWithoutBrokerIsClean(t *testing.T) {
	withHome(t)
	code, out, errOut := runCLI("doctor")
	if code != 0 {
		t.Fatalf("doctor failed: code=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(out, "not running") {
		t.Fatalf("expected broker not-running status, got:\n%s", out)
	}
}

func TestWantsJSONStopsAtDoubleDash(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"flag before --", []string{"--json", "--", "true"}, true},
		{"flag with stdin", []string{"--stdin", "--json"}, true},
		{"literal json in remote command", []string{"--", "echo", "--json"}, false},
		{"no flag", []string{"--", "true"}, false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		if got := wantsJSON(tc.args); got != tc.want {
			t.Errorf("%s: wantsJSON(%v) = %v, want %v", tc.name, tc.args, got, tc.want)
		}
	}
}

func TestStdinBase64PreservesUTF8Command(t *testing.T) {
	command := "echo café ✓\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(command))
	got, err := readStdinCommand(strings.NewReader(encoded), execInputStdinBase64)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != command {
		t.Fatalf("decoded command = %#v, want %q", got, command)
	}
}

func TestStdinRejectsInvalidUTF8BeforeBroker(t *testing.T) {
	withHome(t)
	if code, _, errOut := runCLI("add", "srv1", "tester@127.0.0.1"); code != 0 {
		t.Fatalf("add failed: code=%d stderr=%q", code, errOut)
	}

	var stdout, stderr bytes.Buffer
	code := Run(
		[]string{"srv1", "--stdin"},
		bytes.NewReader([]byte{0xff, 0xfe, 'c', 'a', 'f'}),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("exit code = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	want := "--stdin input is not valid UTF-8 (on Windows PowerShell this usually means the pipe re-encoded it; use --stdin-base64 with UTF-8 base64 instead)"
	if !strings.Contains(stderr.String(), want) {
		t.Fatalf("stderr = %q, want %q", stderr.String(), want)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if broker.NewClient(self).Running() {
		t.Fatal("invalid stdin contacted the broker")
	}
}

func TestStdinAcceptsValidUTF8(t *testing.T) {
	command := "echo café ✓\n"
	got, err := readStdinCommand(strings.NewReader(command), execInputStdin)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != command {
		t.Fatalf("command = %#v, want %q", got, command)
	}
}

func TestParseExecRejectsCombinedInputModes(t *testing.T) {
	cases := [][]string{
		{"--stdin", "--stdin-base64"},
		{"--stdin-base64", "--stdin"},
		{"--stdin-base64", "--", "true"},
	}
	for _, args := range cases {
		if _, _, _, err := parseExec(args); err == nil {
			t.Fatalf("parseExec(%v) accepted combined input modes", args)
		}
	}
}
