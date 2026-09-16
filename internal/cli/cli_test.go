package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/khalid-src/corv-client/internal/audit"
	"github.com/khalid-src/corv-client/internal/broker"
	"github.com/khalid-src/corv-client/internal/paths"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/vault"
)

type inaccessibleSealer struct{}

func (inaccessibleSealer) Seal(data []byte) ([]byte, error) { return data, nil }
func (inaccessibleSealer) Open([]byte) ([]byte, error) {
	return nil, fmt.Errorf("%w: underlying OS failure", vault.ErrKeyAccess)
}

type failingCommandBroker struct {
	err error
}

type responseCommandBroker struct {
	resp broker.Response
}

func (b failingCommandBroker) Exec(string, []string) (broker.Response, error) {
	return broker.Response{}, b.err
}

func (b failingCommandBroker) ExecKeyed(string, []string, string) (broker.Response, error) {
	return broker.Response{}, b.err
}

func (b responseCommandBroker) Exec(string, []string) (broker.Response, error) {
	return b.resp, nil
}

func (b responseCommandBroker) ExecKeyed(string, []string, string) (broker.Response, error) {
	return b.resp, nil
}

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

func TestExecInfrastructureErrorsStayJSON(t *testing.T) {
	tests := []struct {
		name string
		set  func()
		kind string
	}{
		{
			name: "executable",
			set: func() {
				executablePath = func() (string, error) { return "", errors.New("executable unavailable") }
			},
			kind: "local_error",
		},
		{
			name: "broker",
			set: func() {
				executablePath = func() (string, error) { return "corv", nil }
				newCommandBroker = func(string) commandBroker {
					return failingCommandBroker{err: errors.New("broker unavailable")}
				}
			},
			kind: "disconnected",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldExecutable := executablePath
			oldBroker := newCommandBroker
			t.Cleanup(func() {
				executablePath = oldExecutable
				newCommandBroker = oldBroker
			})
			tt.set()

			var stdout, stderr bytes.Buffer
			d := deps{log: audit.NewLog(filepath.Join(t.TempDir(), "audit.jsonl"))}
			code := execCommand(d, profile.Profile{Name: "srv1"}, []string{"true"}, true, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("exit = %d", code)
			}
			if stderr.Len() != 0 {
				t.Fatalf("plain stderr = %q", stderr.String())
			}
			var got map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
				t.Fatalf("invalid json: %v\n%s", err, stdout.String())
			}
			if got["connection"] != "srv1" || got["ok"] != false || got["error_kind"] != tt.kind {
				t.Fatalf("json = %#v", got)
			}
		})
	}
}

func TestDependencyLoadErrorStaysJSON(t *testing.T) {
	oldLoad := loadDependencies
	loadDependencies = func() (deps, error) {
		return deps{}, errors.New("state unavailable")
	}
	t.Cleanup(func() { loadDependencies = oldLoad })

	code, out, errOut := runCLI("srv1", "--json", "--", "true")
	if code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if errOut != "" {
		t.Fatalf("plain stderr = %q", errOut)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out)
	}
	if got["connection"] != "srv1" || got["error_kind"] != "local_error" || got["ok"] != false {
		t.Fatalf("json = %#v", got)
	}
}

func TestStdinCommandIsBounded(t *testing.T) {
	input := strings.NewReader(strings.Repeat("x", 8*1024*1024+1))
	if _, err := readStdinCommand(input, execInputStdin); err == nil || !strings.Contains(err.Error(), "8 MiB") {
		t.Fatalf("error = %v", err)
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

func TestOutputJSONLocalFailuresHaveErrorKinds(t *testing.T) {
	tests := []struct {
		name string
		resp broker.Response
		kind string
	}{
		{name: "bad request", resp: broker.Response{Error: "bad arguments", Kind: "bad_request"}, kind: "bad_request"},
		{name: "local state", resp: broker.Response{Error: "read metadata", Kind: "local_error"}, kind: "local_error"},
		{name: "broker", resp: broker.Response{Error: "broker unavailable", Kind: "disconnected"}, kind: "disconnected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if code := writeOutputJSON(&out, tt.resp); code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			var got map[string]any
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["error_kind"] != tt.kind {
				t.Fatalf("json = %#v", got)
			}
		})
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
	if got["exit_code"] != float64(0) || got["running"] != false {
		t.Fatalf("unexpected state json: %#v", got)
	}
	if got["error_kind"] != "" {
		t.Fatalf("unexpected error kind: %#v", got)
	}
	for _, fabricated := range []string{"connection", "started_at"} {
		if _, ok := got[fabricated]; ok {
			t.Fatalf("output json fabricated %q: %#v", fabricated, got)
		}
	}
}

func TestOutputJSONReportsLossyText(t *testing.T) {
	var out bytes.Buffer
	if code := writeOutputJSON(&out, broker.Response{OK: true, RunID: "run-123", Lossy: true}); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["lossy"] != true {
		t.Fatalf("json = %#v", got)
	}
}

func TestOutputJSONReportsRunningJob(t *testing.T) {
	var out bytes.Buffer
	code := writeOutputJSON(&out, broker.Response{
		OK:       false,
		ExitCode: 75,
		RunID:    "run-123",
		Running:  true,
	})
	if code != 75 {
		t.Fatalf("expected exit 75, got %d", code)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out.String())
	}
	if got["run_id"] != "run-123" || got["running"] != true || got["exit_code"] != float64(75) || got["ok"] != false {
		t.Fatalf("unexpected running json: %#v", got)
	}
}

func TestOutputJSONIncludesPersistedRunOutcome(t *testing.T) {
	startedAt := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Minute)
	var out bytes.Buffer
	code := writeOutputJSON(&out, broker.Response{
		OK:              false,
		ExitCode:        23,
		RunID:           "run-123",
		Stdout:          "failed\n",
		Connection:      "srv1",
		StartedAt:       &startedAt,
		FinishedAt:      &finishedAt,
		Truncated:       true,
		RunMetadata:     true,
		OutputTruncated: true,
		OriginalBytes:   25 * 1024 * 1024,
		SavedBytes:      20 * 1024 * 1024,
		ReturnedBytes:   32768,
	})
	if code != 23 {
		t.Fatalf("expected exit 23, got %d", code)
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
	if got["output_truncated"] != true ||
		got["original_bytes"] != float64(25*1024*1024) ||
		got["saved_bytes"] != float64(20*1024*1024) ||
		got["returned_bytes"] != float64(32768) {
		t.Fatalf("unexpected output metadata: %#v", got)
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

func TestOutputResponseExitContracts(t *testing.T) {
	tests := []struct {
		name string
		resp broker.Response
		code int
	}{
		{name: "running", resp: broker.Response{Running: true, ExitCode: 75, RunID: "run-123"}, code: 75},
		{name: "completed success", resp: broker.Response{OK: true, RunMetadata: true}, code: 0},
		{name: "completed failure", resp: broker.Response{ExitCode: 19, RunMetadata: true}, code: 19},
		{name: "tool error", resp: broker.Response{Error: "unknown run id", Kind: "bad_request"}, code: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var plainOut, plainErr bytes.Buffer
			if code := writeOutputPlain(&plainOut, &plainErr, tt.resp); code != tt.code {
				t.Fatalf("plain exit = %d, want %d", code, tt.code)
			}

			var jsonOut bytes.Buffer
			if code := writeOutputJSON(&jsonOut, tt.resp); code != tt.code {
				t.Fatalf("json exit = %d, want %d", code, tt.code)
			}
			var got map[string]any
			if err := json.Unmarshal(jsonOut.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["exit_code"] != float64(tt.code) {
				t.Fatalf("json exit_code = %#v, want %d", got["exit_code"], tt.code)
			}
		})
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

func TestLogSurfacesRunIDAndStructuredHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log := audit.NewLog(path)
	entry := audit.Entry{
		StartedAt: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		Profile:   "srv1",
		Command:   "deploy",
		ExitCode:  75,
		RunID:     "0000000000000000-aa",
	}
	if err := log.Append(entry); err != nil {
		t.Fatal(err)
	}
	d := deps{log: log}
	var out, errOut bytes.Buffer
	if code := cmdLog(d, nil, &out, &errOut); code != 0 {
		t.Fatalf("plain log exit = %d stderr=%q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "deploy\trun=0000000000000000-aa") {
		t.Fatalf("plain log omitted run id: %q", out.String())
	}

	out.Reset()
	if code := cmdLog(d, []string{"--json"}, &out, &errOut); code != 0 {
		t.Fatalf("json log exit = %d stderr=%q", code, errOut.String())
	}
	var got []audit.Entry
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid log JSON: %v\n%s", err, out.String())
	}
	if len(got) != 1 || got[0].RunID != entry.RunID || got[0].ExitCode != 75 {
		t.Fatalf("log JSON = %#v", got)
	}
}

func TestLogJSONKeepsArgumentErrorsStructured(t *testing.T) {
	d := deps{log: audit.NewLog(filepath.Join(t.TempDir(), "audit.jsonl"))}
	var out, errOut bytes.Buffer
	if code := cmdLog(d, []string{"--json", "--tail"}, &out, &errOut); code != 1 {
		t.Fatalf("exit code = %d", code)
	}
	if errOut.Len() != 0 || !strings.Contains(out.String(), `"error_kind":"bad_request"`) {
		t.Fatalf("stdout=%q stderr=%q", out.String(), errOut.String())
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
	p, err := paths.Default()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(p.Root, "broker.json")); !os.IsNotExist(err) {
		t.Fatalf("doctor started or published a broker: %v", err)
	}
}

func TestDoctorSurfacesBrokerInspectionFailure(t *testing.T) {
	withHome(t)
	original := newDoctorClient
	newDoctorClient = func(string) statusClient {
		return fakeStatusClient{err: errors.New("private endpoint detail")}
	}
	t.Cleanup(func() { newDoctorClient = original })

	code, out, errOut := runCLI("doctor")
	if code != 1 || errOut != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if !strings.Contains(out, "broker:           unavailable") || strings.Contains(out, "private endpoint detail") {
		t.Fatalf("doctor output = %q", out)
	}

	code, out, errOut = runCLI("doctor", "--full")
	if code != 1 || errOut != "" || !strings.Contains(out, "private endpoint detail") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

func TestDoctorDistinguishesInaccessiblePathFromMissing(t *testing.T) {
	label, ok := presentLabel("\x00", false)
	if ok || !strings.Contains(label, "unavailable") || strings.Contains(label, "invalid") {
		t.Fatalf("label=%q ok=%v", label, ok)
	}
}

func TestExecReportsAuditWriteFailureWithoutChangingOutcome(t *testing.T) {
	originalExecutable := executablePath
	originalBroker := newCommandBroker
	executablePath = func() (string, error) { return "corv", nil }
	newCommandBroker = func(string) commandBroker {
		return responseCommandBroker{resp: broker.Response{OK: true, Stdout: "done\n"}}
	}
	t.Cleanup(func() {
		executablePath = originalExecutable
		newCommandBroker = originalBroker
	})

	var stdout, stderr bytes.Buffer
	d := deps{log: audit.NewLog(t.TempDir())}
	code := execCommand(d, profile.Profile{Name: "srv1"}, []string{"true"}, true, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	highlights, ok := got["highlights"].([]any)
	if !ok || len(highlights) != 1 || highlights[0] != "local command history could not be written" {
		t.Fatalf("json = %#v", got)
	}
}

func TestExecFinalizationFailureReturnsToolError(t *testing.T) {
	originalExecutable := executablePath
	originalBroker := newCommandBroker
	executablePath = func() (string, error) { return "corv", nil }
	newCommandBroker = func(string) commandBroker {
		return responseCommandBroker{resp: broker.Response{
			OK:       false,
			ExitCode: 1,
			Error:    "run finished, but Corv could not save its log locally; remote copy retained",
			Kind:     "local_error",
			RunID:    "run-123",
		}}
	}
	t.Cleanup(func() {
		executablePath = originalExecutable
		newCommandBroker = originalBroker
	})

	var stdout, stderr bytes.Buffer
	d := deps{log: audit.NewLog(filepath.Join(t.TempDir(), "audit.jsonl"))}
	code := execCommand(d, profile.Profile{Name: "srv1"}, []string{"true"}, true, &stdout, &stderr)
	if code != 1 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["ok"] != false || got["exit_code"] != float64(1) || got["error_kind"] != "local_error" {
		t.Fatalf("json = %#v", got)
	}
}

func TestDoctorExplainsVaultAccessContextWithoutLeakingRawError(t *testing.T) {
	withHome(t)
	p, err := paths.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p.ConfigFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.ConfigFile, []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := deps{
		store:   profile.NewStore(p.ConfigFile, inaccessibleSealer{}),
		secrets: vault.New(p.VaultFile, p.VaultKey),
		log:     audit.NewLog(p.AuditFile),
		paths:   p,
	}
	var out, errOut bytes.Buffer
	if code := cmdDoctor(d, nil, &out, &errOut); code != 1 {
		t.Fatalf("doctor exit = %d, stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "vault:            unreadable") ||
		!strings.Contains(out.String(), "process context") {
		t.Fatalf("doctor output = %q", out.String())
	}
	if strings.Contains(out.String(), "underlying OS failure") {
		t.Fatalf("default doctor leaked raw error: %q", out.String())
	}

	out.Reset()
	if code := cmdDoctor(d, []string{"--full"}, &out, &errOut); code != 1 {
		t.Fatalf("full doctor exit = %d", code)
	}
	if !strings.Contains(out.String(), "underlying OS failure") {
		t.Fatalf("full doctor omitted raw cause: %q", out.String())
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
		if _, _, _, _, err := parseExec(args); err == nil {
			t.Fatalf("parseExec(%v) accepted combined input modes", args)
		}
	}
}

func TestParseExecRunKey(t *testing.T) {
	command, asJSON, input, runKey, err := parseExec([]string{"--json", "--run-key", "change-42", "--", "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	if !asJSON || input != execInputArgs || runKey != "change-42" || len(command) != 1 || command[0] != "deploy" {
		t.Fatalf("parse result: command=%v json=%v input=%v runKey=%q", command, asJSON, input, runKey)
	}
	for _, args := range [][]string{
		{"--run-key"},
		{"--run-key", "bad key", "--", "true"},
		{"--run-key", "one", "--run-key", "two", "--", "true"},
	} {
		if _, _, _, _, err := parseExec(args); err == nil {
			t.Fatalf("parseExec(%v) accepted invalid run key", args)
		}
	}
}
