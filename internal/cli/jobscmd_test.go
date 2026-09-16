package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/khalid-src/corv-client/internal/broker"
)

type fakeJobsClient struct {
	runs []broker.RunInfo
	err  error
}

func jobsExitCode(code int) *int { return &code }

func (c fakeJobsClient) Jobs() ([]broker.RunInfo, error) { return c.runs, c.err }

func TestJobsJSONIsStructuredAndPrivacySafe(t *testing.T) {
	original := newJobsClient
	newJobsClient = func(string) jobsClient {
		return fakeJobsClient{runs: []broker.RunInfo{{
			RunID: "0000000000000000-aa", Connection: "prod", Status: "running", Running: true,
			ExitCode: jobsExitCode(75), StartedAt: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		}}}
	}
	t.Cleanup(func() { newJobsClient = original })
	var out, errOut bytes.Buffer
	if code := cmdJobs([]string{"--json"}, &out, &errOut); code != 0 {
		t.Fatalf("jobs exit = %d stderr=%q", code, errOut.String())
	}
	var got struct {
		OK   bool             `json:"ok"`
		Runs []broker.RunInfo `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.OK || len(got.Runs) != 1 || got.Runs[0].Connection != "prod" || !got.Runs[0].Running || got.Runs[0].ExitCode == nil || *got.Runs[0].ExitCode != 75 {
		t.Fatalf("jobs JSON = %#v", got)
	}
	if strings.Contains(out.String(), "target") || strings.Contains(out.String(), "host") {
		t.Fatalf("jobs JSON exposed connection details: %s", out.String())
	}
}

func TestJobsJSONKeepsErrorsStructured(t *testing.T) {
	original := newJobsClient
	newJobsClient = func(string) jobsClient { return fakeJobsClient{err: errors.New("broker unavailable")} }
	t.Cleanup(func() { newJobsClient = original })
	var out, errOut bytes.Buffer
	if code := cmdJobs([]string{"--json"}, &out, &errOut); code != 1 {
		t.Fatalf("jobs exit = %d", code)
	}
	if errOut.Len() != 0 || !strings.Contains(out.String(), `"ok": false`) ||
		!strings.Contains(out.String(), `"error_kind": "local_error"`) || !strings.Contains(out.String(), "broker unavailable") {
		t.Fatalf("stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

func TestJobsJSONOmitsUnknownExitCode(t *testing.T) {
	original := newJobsClient
	newJobsClient = func(string) jobsClient {
		return fakeJobsClient{runs: []broker.RunInfo{{
			RunID: "0000000000000000-aa", Connection: "prod", Status: "unknown",
			StartedAt: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		}}}
	}
	t.Cleanup(func() { newJobsClient = original })

	var out, errOut bytes.Buffer
	if code := cmdJobs([]string{"--json"}, &out, &errOut); code != 0 {
		t.Fatalf("jobs exit = %d stderr=%q", code, errOut.String())
	}
	if strings.Contains(out.String(), `"exit_code"`) {
		t.Fatalf("jobs JSON invented an exit code: %s", out.String())
	}
}

func TestJobsJSONClassifiesArgumentErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := cmdJobs([]string{"--json", "extra"}, &out, &errOut); code != 1 {
		t.Fatalf("jobs exit = %d", code)
	}
	if errOut.Len() != 0 || !strings.Contains(out.String(), `"error_kind": "bad_request"`) {
		t.Fatalf("stdout=%q stderr=%q", out.String(), errOut.String())
	}
}
