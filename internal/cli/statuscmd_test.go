package cli

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/khalid-src/corv-client/internal/broker"
)

type fakeStatusClient struct {
	running     bool
	connections []broker.StatusInfo
	err         error
}

func (c fakeStatusClient) Status() (bool, []broker.StatusInfo, error) {
	return c.running, c.connections, c.err
}

func TestStatusDoesNotStartMissingBroker(t *testing.T) {
	withHome(t)
	code, out, errOut := runCLI("status")
	if code != 0 || errOut != "" || out != "no warm connections (broker not running)\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

func TestStatusDoesNotLoadConnectionDependencies(t *testing.T) {
	withHome(t)
	original := loadDependencies
	loadDependencies = func() (deps, error) { return deps{}, errors.New("should not load") }
	t.Cleanup(func() { loadDependencies = original })

	code, out, errOut := runCLI("status", "--json")
	if code != 0 || errOut != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	var got statusResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.BrokerRunning || got.Connections == nil {
		t.Fatalf("status = %#v", got)
	}
}

func TestStatusFormatsPlainAndJSON(t *testing.T) {
	original := newStatusClient
	newStatusClient = func(string) statusClient {
		return fakeStatusClient{running: true, connections: []broker.StatusInfo{
			{Name: "web", Target: "deploy@192.0.2.10", IdleMS: 4200, RunningJobs: 2},
		}}
	}
	t.Cleanup(func() { newStatusClient = original })

	var plainOut, plainErr strings.Builder
	if code := cmdStatus(nil, &plainOut, &plainErr); code != 0 || plainErr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, plainOut.String(), plainErr.String())
	}
	for _, want := range []string{"NAME", "IDLE", "RUNS", "web", "4s", "2", "exits automatically"} {
		if !strings.Contains(plainOut.String(), want) {
			t.Fatalf("plain status missing %q:\n%s", want, plainOut.String())
		}
	}
	for _, private := range []string{"TARGET", "@", "192.0.2.10"} {
		if strings.Contains(plainOut.String(), private) {
			t.Fatalf("plain status exposed %q:\n%s", private, plainOut.String())
		}
	}

	var jsonOut, jsonErr strings.Builder
	if code := cmdStatus([]string{"--json"}, &jsonOut, &jsonErr); code != 0 || jsonErr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, jsonOut.String(), jsonErr.String())
	}
	var got statusResult
	if err := json.Unmarshal([]byte(jsonOut.String()), &got); err != nil {
		t.Fatal(err)
	}
	if !got.BrokerRunning || len(got.Connections) != 1 || got.Connections[0].RunningJobs != 2 || got.Connections[0].IdleSeconds != 4 {
		t.Fatalf("status = %#v", got)
	}
	if got.Connections[0].Target != "" || strings.Contains(jsonOut.String(), "192.0.2.10") {
		t.Fatalf("default JSON exposed target: %s", jsonOut.String())
	}

	plainOut.Reset()
	plainErr.Reset()
	if code := cmdStatus([]string{"--full"}, &plainOut, &plainErr); code != 0 || plainErr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, plainOut.String(), plainErr.String())
	}
	if !strings.Contains(plainOut.String(), "TARGET") || !strings.Contains(plainOut.String(), "deploy@192.0.2.10") {
		t.Fatalf("full status omitted target:\n%s", plainOut.String())
	}

	jsonOut.Reset()
	jsonErr.Reset()
	if code := cmdStatus([]string{"--json", "--full"}, &jsonOut, &jsonErr); code != 0 || jsonErr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, jsonOut.String(), jsonErr.String())
	}
	if err := json.Unmarshal([]byte(jsonOut.String()), &got); err != nil {
		t.Fatal(err)
	}
	if got.Connections[0].Target != "deploy@192.0.2.10" {
		t.Fatalf("full JSON target = %q", got.Connections[0].Target)
	}
}

func TestStatusRejectsDuplicateFlags(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := cmdStatus([]string{"--json", "--json"}, &stdout, &stderr); code != 1 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var got statusResult
	if err := json.Unmarshal([]byte(stdout.String()), &got); err != nil {
		t.Fatal(err)
	}
	if got.Error == "" {
		t.Fatalf("status = %#v", got)
	}
}

func TestStatusJSONFailureStaysJSON(t *testing.T) {
	original := newStatusClient
	newStatusClient = func(string) statusClient { return fakeStatusClient{err: errors.New("endpoint unreadable")} }
	t.Cleanup(func() { newStatusClient = original })

	var stdout, stderr strings.Builder
	if code := cmdStatus([]string{"--json"}, &stdout, &stderr); code != 1 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var got statusResult
	if err := json.Unmarshal([]byte(stdout.String()), &got); err != nil {
		t.Fatal(err)
	}
	if got.Error != "endpoint unreadable" || got.Connections == nil {
		t.Fatalf("status = %#v", got)
	}
}
