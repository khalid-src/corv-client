package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/sshconn"
)

func TestConnectionTestSuccessClosesOneOffConnection(t *testing.T) {
	d := connectionTestDeps(t, profile.Profile{Name: "srv1", Target: "tester@example.com"})
	closed := false
	var gotOptions sshconn.DialOptions
	setDiagnosticHooks(t,
		func(context.Context, string) ([]string, error) { return []string{"192.0.2.10"}, nil },
		successfulTCPDial,
		func(_ profile.Profile, opt sshconn.DialOptions) (io.Closer, error) {
			gotOptions = opt
			return closeFunc(func() error { closed = true; return nil }), nil
		},
	)

	var stdout, stderr strings.Builder
	code := cmdTest(d, []string{"srv1", "--json"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var result connectionTestResult
	if err := json.Unmarshal([]byte(stdout.String()), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.FirstFailure != nil || result.ErrorKind != "" || !closed {
		t.Fatalf("result=%#v closed=%v", result, closed)
	}
	for _, private := range []string{"example.com", "192.0.2.10"} {
		if strings.Contains(stdout.String(), private) {
			t.Fatalf("default test output exposed %q: %s", private, stdout.String())
		}
	}
	if gotOptions.AllowNewHost || gotOptions.Prompt != nil {
		t.Fatalf("diagnostic dial may not trust a new host: %#v", gotOptions)
	}
	for _, stage := range []string{"resolve", "tcp", "handshake", "hostkey", "auth"} {
		if !hasTestStage(result, stage, "ok") {
			t.Fatalf("missing successful %s stage: %#v", stage, result.Stages)
		}
	}

	closed = false
	stdout.Reset()
	stderr.Reset()
	code = cmdTest(d, []string{"srv1", "--json", "--full"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 || !closed {
		t.Fatalf("code=%d stdout=%q stderr=%q closed=%v", code, stdout.String(), stderr.String(), closed)
	}
	if !strings.Contains(stdout.String(), "example.com") || !strings.Contains(stdout.String(), "192.0.2.10") {
		t.Fatalf("full test output omitted connection details: %s", stdout.String())
	}

	closed = false
	stdout.Reset()
	stderr.Reset()
	code = cmdTest(d, []string{"srv1"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 || !closed {
		t.Fatalf("code=%d stdout=%q stderr=%q closed=%v", code, stdout.String(), stderr.String(), closed)
	}
	for _, private := range []string{"example.com", "192.0.2.10"} {
		if strings.Contains(stdout.String(), private) {
			t.Fatalf("default plain test output exposed %q: %s", private, stdout.String())
		}
	}
}

func TestConnectionTestUsesSSHRouteForPrivateEndpoints(t *testing.T) {
	d := connectionTestDeps(t, profile.Profile{
		Name: "srv1", Target: "app@private.internal", ProxyJump: "ops@edge.example,ops@middle.internal",
	})
	var lookedUp []string
	var tcpAddresses []string
	setDiagnosticHooks(t,
		func(_ context.Context, host string) ([]string, error) {
			lookedUp = append(lookedUp, host)
			return []string{"192.0.2.20"}, nil
		},
		func(_ context.Context, address string) (net.Conn, error) {
			tcpAddresses = append(tcpAddresses, address)
			return successfulTCPDial(context.Background(), address)
		},
		func(_ profile.Profile, opt sshconn.DialOptions) (io.Closer, error) {
			if len(opt.JumpHosts) != 2 {
				t.Fatalf("jump hosts = %#v", opt.JumpHosts)
			}
			return closeFunc(func() error { return nil }), nil
		},
	)

	result := testSavedConnection(d, "srv1")
	if !result.OK {
		t.Fatalf("result = %#v", result)
	}
	if len(lookedUp) != 1 || lookedUp[0] != "edge.example" {
		t.Fatalf("local lookups = %#v", lookedUp)
	}
	if len(tcpAddresses) != 1 || !strings.Contains(tcpAddresses[0], "edge.example") {
		t.Fatalf("local TCP probes = %#v", tcpAddresses)
	}
	if !hasTestStage(result, "jump", "ok") || !hasTestStage(result, "tcp", "warn") {
		t.Fatalf("route stages = %#v", result.Stages)
	}
}

func TestConnectionTestSurfacesVaultFailureAsLocalError(t *testing.T) {
	p := profile.Profile{Name: "srv1", Target: "tester@example.com", SecretRef: "profile:srv1"}
	d := connectionTestDeps(t, p)
	if err := os.WriteFile(d.paths.VaultFile, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	sshCalled := false
	setDiagnosticHooks(t,
		func(context.Context, string) ([]string, error) { return []string{"192.0.2.10"}, nil },
		successfulTCPDial,
		func(profile.Profile, sshconn.DialOptions) (io.Closer, error) {
			sshCalled = true
			return nil, errors.New("unexpected SSH dial")
		},
	)

	result := testSavedConnection(d, "srv1")
	if result.OK || result.ErrorKind != "local_error" || result.failureStage() != "auth" || sshCalled {
		t.Fatalf("result=%#v sshCalled=%v", result, sshCalled)
	}
	if !strings.Contains(result.failureDetail(), "stored credentials") {
		t.Fatalf("detail = %q", result.failureDetail())
	}
}

func TestConnectionTestUnknownProfileJSON(t *testing.T) {
	withHome(t)
	code, out, errOut := runCLI("test", "missing", "--json")
	if code != 1 || errOut != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	var result connectionTestResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.OK || result.ErrorKind != "unknown_connection" || result.Connection != "missing" {
		t.Fatalf("result = %#v", result)
	}
}

func TestConnectionTestDependencyFailureStaysJSON(t *testing.T) {
	original := loadDependencies
	loadDependencies = func() (deps, error) { return deps{}, errors.New("config unavailable") }
	t.Cleanup(func() { loadDependencies = original })

	code, out, errOut := runCLI("test", "srv1", "--json")
	if code != 1 || errOut != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	var result connectionTestResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.ErrorKind != "local_error" || result.Connection != "srv1" || result.failureDetail() != "local configuration error" {
		t.Fatalf("result = %#v", result)
	}
}

func TestConnectionTestRejectsDuplicateFlags(t *testing.T) {
	d := connectionTestDeps(t, profile.Profile{Name: "srv1", Target: "tester@example.com"})
	var stdout, stderr strings.Builder
	code := cmdTest(d, []string{"srv1", "--json", "--json"}, &stdout, &stderr)
	if code != 1 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var result connectionTestResult
	if err := json.Unmarshal([]byte(stdout.String()), &result); err != nil {
		t.Fatal(err)
	}
	if result.ErrorKind != "bad_request" {
		t.Fatalf("result = %#v", result)
	}
}

func TestConnectionTestDoesNotMisclassifyHandshakeAsAuth(t *testing.T) {
	d := connectionTestDeps(t, profile.Profile{Name: "srv1", Target: "tester@example.com"})
	setDiagnosticHooks(t,
		func(context.Context, string) ([]string, error) { return []string{"192.0.2.10"}, nil },
		successfulTCPDial,
		func(profile.Profile, sshconn.DialOptions) (io.Closer, error) {
			return nil, errors.New("ssh: handshake failed: EOF")
		},
	)

	result := testSavedConnection(d, "srv1")
	if result.failureStage() != "handshake" || result.ErrorKind != "ssh_error" {
		t.Fatalf("result = %#v", result)
	}
}

func TestConnectionTestClassifiesLocalIdentityFailure(t *testing.T) {
	d := connectionTestDeps(t, profile.Profile{Name: "srv1", Target: "tester@example.com"})
	setDiagnosticHooks(t,
		func(context.Context, string) ([]string, error) { return []string{"192.0.2.10"}, nil },
		successfulTCPDial,
		func(profile.Profile, sshconn.DialOptions) (io.Closer, error) {
			return nil, errors.New("load identity file: access denied")
		},
	)

	result := testSavedConnection(d, "srv1")
	if result.failureStage() != "auth" || result.ErrorKind != "local_error" {
		t.Fatalf("result = %#v", result)
	}
}

func TestConnectionTestClassifiesKnownHostsFailure(t *testing.T) {
	d := connectionTestDeps(t, profile.Profile{Name: "srv1", Target: "tester@example.com"})
	setDiagnosticHooks(t,
		func(context.Context, string) ([]string, error) { return []string{"192.0.2.10"}, nil },
		successfulTCPDial,
		func(profile.Profile, sshconn.DialOptions) (io.Closer, error) {
			return nil, errors.New("knownhosts: read failed")
		},
	)

	result := testSavedConnection(d, "srv1")
	if result.failureStage() != "hostkey" || result.ErrorKind != "host_key" {
		t.Fatalf("result = %#v", result)
	}
}

func connectionTestDeps(t *testing.T, p profile.Profile) deps {
	t.Helper()
	t.Setenv("CORV_HOME", t.TempDir())
	d, err := loadDeps()
	if err != nil {
		t.Fatal(err)
	}
	reg := profile.Registry{}
	if err := reg.Set(p); err != nil {
		t.Fatal(err)
	}
	if err := d.store.Save(reg); err != nil {
		t.Fatal(err)
	}
	return d
}

func setDiagnosticHooks(
	t *testing.T,
	lookup func(context.Context, string) ([]string, error),
	tcp func(context.Context, string) (net.Conn, error),
	sshDial func(profile.Profile, sshconn.DialOptions) (io.Closer, error),
) {
	t.Helper()
	oldLookup, oldTCP, oldSSH := diagnosticLookupHost, diagnosticDialTCP, diagnosticDialSSH
	diagnosticLookupHost, diagnosticDialTCP, diagnosticDialSSH = lookup, tcp, sshDial
	t.Cleanup(func() {
		diagnosticLookupHost, diagnosticDialTCP, diagnosticDialSSH = oldLookup, oldTCP, oldSSH
	})
}

func successfulTCPDial(context.Context, string) (net.Conn, error) {
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func hasTestStage(result connectionTestResult, stage, status string) bool {
	for _, got := range result.Stages {
		if got.Stage == stage && got.Status == status {
			return true
		}
	}
	return false
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }
