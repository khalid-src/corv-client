package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/sshconn"
)

const connectionTestTimeout = 15 * time.Second

type connectionTestStage struct {
	Stage  string `json:"stage"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type connectionTestResult struct {
	OK           bool                  `json:"ok"`
	Connection   string                `json:"connection"`
	Stages       []connectionTestStage `json:"stages"`
	FirstFailure *string               `json:"first_failure"`
	ErrorKind    string                `json:"error_kind"`
}

type diagnosticEndpoint struct {
	host   string
	port   int
	label  string
	routed bool
}

var (
	diagnosticLookupHost = net.DefaultResolver.LookupHost
	diagnosticDialTCP    = func(ctx context.Context, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: connectionTestTimeout}).DialContext(ctx, "tcp", address)
	}
	diagnosticDialSSH = func(p profile.Profile, opt sshconn.DialOptions) (io.Closer, error) {
		return sshconn.Dial(p, opt)
	}
)

func cmdTest(d deps, args []string, stdout, stderr io.Writer) int {
	name, asJSON, full, err := parseTestArgs(args)
	if err != nil {
		if asJSON {
			result := failedConnectionTest(name, "local", "bad_request", err.Error())
			if !full {
				result = privateConnectionTestResult(result)
			}
			return writeConnectionTestJSON(stdout, result)
		}
		return fail(stderr, err)
	}
	result := testSavedConnection(d, name)
	if !full {
		result = privateConnectionTestResult(result)
	}
	if asJSON {
		return writeConnectionTestJSON(stdout, result)
	}
	writeConnectionTestPlain(stdout, result)
	if result.OK {
		return 0
	}
	return 1
}

func parseTestArgs(args []string) (string, bool, bool, error) {
	var name string
	asJSON := false
	full := false
	for _, arg := range args {
		switch arg {
		case "--json":
			if asJSON {
				return name, asJSON, full, errors.New("usage: corv test <name> [--json] [--full]")
			}
			asJSON = true
		case "--full":
			if full {
				return name, asJSON, full, errors.New("usage: corv test <name> [--json] [--full]")
			}
			full = true
		default:
			if strings.HasPrefix(arg, "-") || name != "" {
				return name, asJSON, full, errors.New("usage: corv test <name> [--json] [--full]")
			}
			name = arg
		}
	}
	if name == "" {
		return "", asJSON, full, errors.New("usage: corv test <name> [--json] [--full]")
	}
	return name, asJSON, full, nil
}

func testSavedConnection(d deps, name string) connectionTestResult {
	state, ok, err := loadConnectionState(d, name)
	if err != nil {
		var stateErr *connectionStateError
		if errors.As(err, &stateErr) {
			return failedConnectionTest(name, stateErr.stage, stateErr.kind, stateErr.Error())
		}
		return failedConnectionTest(name, "local", "local_error", err.Error())
	}
	if !ok {
		return failedConnectionTest(name, "local", "unknown_connection", fmt.Sprintf("unknown connection %q", name))
	}
	return runConnectionTest(state)
}

func runConnectionTest(state connectionState) connectionTestResult {
	p := state.profile
	result := connectionTestResult{Connection: p.Name, Stages: []connectionTestStage{}}

	endpoints := diagnosticEndpoints(p, state.jumps)
	for _, endpoint := range endpoints {
		if endpoint.routed {
			result.add("resolve", "warn", endpoint.label+" is resolved through the SSH route")
			result.add("tcp", "warn", endpoint.label+" is reached through the SSH route")
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), connectionTestTimeout)
		addresses, lookupErr := diagnosticLookupHost(ctx, endpoint.host)
		cancel()
		if lookupErr != nil {
			return result.fail("resolve", "fail", endpoint.label+": "+lookupErr.Error(), string(sshconn.Classify(lookupErr)))
		}
		result.add("resolve", "ok", endpoint.label+" -> "+strings.Join(addresses, ", "))

		ctx, cancel = context.WithTimeout(context.Background(), connectionTestTimeout)
		conn, dialErr := diagnosticDialTCP(ctx, net.JoinHostPort(endpoint.host, strconv.Itoa(endpoint.port)))
		cancel()
		if dialErr != nil {
			return result.fail("tcp", "fail", endpoint.label+": "+dialErr.Error(), string(sshconn.Classify(dialErr)))
		}
		_ = conn.Close()
		result.add("tcp", "ok", endpoint.label+" accepts TCP connections")
	}

	if state.authErr != nil {
		return result.fail("auth", "fail", state.authErr.Error(), "local_error")
	}
	conn, err := diagnosticDialSSH(p, sshconn.DialOptions{
		Password:   state.secret.Password,
		Passphrase: state.secret.Passphrase,
		Timeout:    connectionTestTimeout,
		JumpHosts:  state.jumps,
	})
	if err != nil {
		return classifyConnectionTestFailure(result, err, len(state.jumps) > 0)
	}
	_ = conn.Close()
	if len(state.jumps) > 0 {
		result.add("jump", "ok", fmt.Sprintf("SSH route established through %d bastion hop(s)", len(state.jumps)))
	}
	result.add("handshake", "ok", "SSH transport established")
	result.add("hostkey", "ok", "host keys are trusted")
	result.add("auth", "ok", "stored authentication succeeded")
	result.OK = true
	return result
}

func diagnosticEndpoints(p profile.Profile, jumps []sshconn.JumpHost) []diagnosticEndpoint {
	endpoints := make([]diagnosticEndpoint, 0, len(jumps)+1)
	for i, jump := range jumps {
		port := jump.Port
		if port == 0 {
			port = 22
		}
		endpoints = append(endpoints, diagnosticEndpoint{
			host: jump.Host, port: port,
			label:  fmt.Sprintf("jump %d (%s)", i+1, net.JoinHostPort(jump.Host, strconv.Itoa(port))),
			routed: i > 0,
		})
	}
	_, host := splitDiagnosticTarget(p.Target)
	port := p.Port
	if port == 0 {
		port = 22
	}
	endpoints = append(endpoints, diagnosticEndpoint{
		host: host, port: port,
		label:  "target (" + net.JoinHostPort(host, strconv.Itoa(port)) + ")",
		routed: len(jumps) > 0,
	})
	return endpoints
}

func splitDiagnosticTarget(target string) (string, string) {
	if at := strings.LastIndex(target, "@"); at > 0 {
		return target[:at], strings.Trim(target[at+1:], "[]")
	}
	return "", strings.Trim(target, "[]")
}

func classifyConnectionTestFailure(result connectionTestResult, err error, hasJumps bool) connectionTestResult {
	kind := sshconn.Classify(err)
	var hostKeyErr *sshconn.HostKeyError
	switch {
	case errors.As(err, &hostKeyErr):
		status := "warn"
		detail := "host key is unknown; connect interactively once to review it"
		if hostKeyErr.Changed {
			status = "fail"
			detail = "host key changed; verify the server before updating known_hosts"
		}
		return result.fail("hostkey", status, detail, string(kind))
	case kind == sshconn.ErrHostKey:
		return result.fail("hostkey", "fail", err.Error(), string(kind))
	case isLocalAuthFailure(err):
		return result.fail("auth", "fail", err.Error(), "local_error")
	case kind == sshconn.ErrAuth && isRemoteAuthFailure(err):
		result.add("handshake", "ok", "SSH transport and host-key verification completed")
		result.add("hostkey", "ok", "host keys are trusted")
		return result.fail("auth", "fail", err.Error(), string(kind))
	case kind == sshconn.ErrUnknownHost:
		return result.fail("resolve", "fail", err.Error(), string(kind))
	case hasJumps && strings.Contains(strings.ToLower(err.Error()), "jump"):
		return result.fail("jump", "fail", err.Error(), string(kind))
	case kind == sshconn.ErrAuth:
		return result.fail("handshake", "fail", err.Error(), string(sshconn.ErrSSH))
	default:
		return result.fail("handshake", "fail", err.Error(), string(kind))
	}
}

func isLocalAuthFailure(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "load identity file") ||
		strings.Contains(message, "no authentication methods available") ||
		strings.Contains(message, "no jump authentication methods available")
}

func isRemoteAuthFailure(err error) bool {
	message := strings.ToLower(err.Error())
	for _, phrase := range []string{
		"unable to authenticate",
		"no supported methods",
		"no authentication methods",
		"permission denied",
	} {
		if strings.Contains(message, phrase) {
			return true
		}
	}
	return false
}

func failedConnectionTest(name, stage, kind, detail string) connectionTestResult {
	return connectionTestResult{Connection: name, Stages: []connectionTestStage{}}.fail(stage, "fail", detail, kind)
}

func privateConnectionTestResult(result connectionTestResult) connectionTestResult {
	private := result
	private.Stages = append([]connectionTestStage(nil), result.Stages...)
	for i := range private.Stages {
		stage := &private.Stages[i]
		switch stage.Stage {
		case "local":
			if result.ErrorKind == "unknown_connection" {
				stage.Detail = "connection is not saved"
			} else {
				stage.Detail = "local configuration error"
			}
		case "resolve":
			stage.Detail = diagnosticStatusDetail(stage.Status, "name resolution", "resolved through the SSH route")
		case "tcp":
			stage.Detail = diagnosticStatusDetail(stage.Status, "TCP connection", "reached through the SSH route")
		case "jump":
			stage.Detail = diagnosticStatusDetail(stage.Status, "bastion route", "bastion route")
		case "handshake":
			stage.Detail = diagnosticStatusDetail(stage.Status, "SSH handshake", "SSH handshake")
		case "hostkey":
			stage.Detail = diagnosticStatusDetail(stage.Status, "host-key verification", "host-key verification")
		case "auth":
			stage.Detail = diagnosticStatusDetail(stage.Status, "authentication", "authentication")
		}
	}
	return private
}

func diagnosticStatusDetail(status, label, warning string) string {
	switch status {
	case "ok":
		return label + " succeeded"
	case "warn":
		return warning
	default:
		return label + " failed"
	}
}

func (r connectionTestResult) fail(stage, status, detail, kind string) connectionTestResult {
	r.add(stage, status, detail)
	r.OK = false
	r.ErrorKind = kind
	r.FirstFailure = &r.Stages[len(r.Stages)-1].Stage
	return r
}

func (r *connectionTestResult) add(stage, status, detail string) {
	r.Stages = append(r.Stages, connectionTestStage{Stage: stage, Status: status, Detail: detail})
}

func (r connectionTestResult) failureStage() string {
	if r.FirstFailure == nil {
		return "connection test failed"
	}
	return *r.FirstFailure
}

func (r connectionTestResult) failureDetail() string {
	if r.FirstFailure == nil {
		return "no diagnostic detail available"
	}
	for i := len(r.Stages) - 1; i >= 0; i-- {
		if r.Stages[i].Stage == *r.FirstFailure {
			return r.Stages[i].Detail
		}
	}
	return "no diagnostic detail available"
}

func writeConnectionTestPlain(w io.Writer, result connectionTestResult) {
	fmt.Fprintf(w, "connection: %s\n", result.Connection)
	for _, stage := range result.Stages {
		label := stage.Status
		if label == "fail" {
			label = "FAIL"
		}
		fmt.Fprintf(w, "[%s] %-10s %s\n", label, stage.Stage, stage.Detail)
	}
	if !result.OK {
		fmt.Fprintf(w, "fix: %s for %s: %s\n", result.failureStage(), result.Connection, connectionTestHint(result))
	}
}

func connectionTestHint(result connectionTestResult) string {
	switch result.failureStage() {
	case "resolve":
		return "check the host name and DNS"
	case "tcp":
		return "check the port, firewall, and network route"
	case "jump":
		return "check the bastion route and its saved profile"
	case "hostkey":
		return "connect interactively to review an unknown key; investigate a changed key"
	case "auth":
		return "check the saved credential, identity file, and SSH agent"
	default:
		return result.failureDetail()
	}
}

func writeConnectionTestJSON(w io.Writer, result connectionTestResult) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
	if result.OK {
		return 0
	}
	return 1
}
