package cli

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/khalid-src/corv-client/internal/audit"
	"github.com/khalid-src/corv-client/internal/broker"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/sshconn"
	"github.com/khalid-src/corv-client/internal/statelock"
	"github.com/khalid-src/corv-client/internal/tui"
	"github.com/khalid-src/corv-client/internal/vault"
)

type commandBroker interface {
	Exec(string, []string) (broker.Response, error)
	ExecKeyed(string, []string, string) (broker.Response, error)
}

var (
	executablePath   = os.Executable
	newCommandBroker = func(self string) commandBroker { return broker.NewClient(self) }
)

// runManager opens the TUI, and when the user picks a connection, opens it.
// After the interactive session ends the TUI reopens (exit-to-home). The loop
// exits only when the user quits from the home screen (q / Ctrl+C).
func runManager(d deps, stdin io.Reader, stdout, stderr io.Writer) int {
	if !isInteractive() {
		return fail(stderr, errors.New("the interactive UI needs a terminal; use `corv <name>` to connect directly"))
	}
	var notice string
	for {
		testConnection := func(name string) (string, error) {
			result := testSavedConnection(d, name)
			if result.OK {
				return name + ": connection test passed", nil
			}
			return "", fmt.Errorf("%s: %s", result.failureStage(), result.failureDetail())
		}
		name, err := tui.Run(d.store, d.secrets, d.log, stdin, stdout, notice, testConnection)
		if err != nil {
			return fail(stderr, err)
		}
		if name == "" {
			return 0
		}
		notice = ""
		if err := openInteractive(d, name, stderr); err != nil {
			// Carry the failure back into the TUI as a branded notice rather than
			// printing to the bare terminal and reading stdin, which is unreliable
			// right after Bubble Tea releases the console (it left the prompt stuck).
			notice = fmt.Sprintf("could not connect to %s: %v", name, err)
		}
		// session ended - loop back to the home screen
	}
}

// cmdConnect handles `corv <name>` and `corv <name> -- <cmd>`.
func cmdConnect(d deps, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	name := args[0]
	asJSON := wantsJSON(args[1:])
	reg, err := d.store.Load()
	if err != nil {
		if asJSON {
			return writeExecErrorJSON(stdout, name, "bad_request", err.Error())
		}
		return fail(stderr, err)
	}
	p, ok := reg.Get(name)
	if !ok {
		if asJSON {
			return writeExecErrorJSON(stdout, name, "unknown_connection", fmt.Sprintf("unknown connection %q (try `corv list`)", name))
		}
		return fail(stderr, fmt.Errorf("unknown connection %q (try `corv list`)", name))
	}

	rest := args[1:]
	if len(rest) == 0 {
		code, err := interactiveConnect(d, p.Name, stderr)
		if err != nil {
			return fail(stderr, err)
		}
		return code
	}

	command, asJSON, input, runKey, err := parseExec(rest)
	if err != nil {
		if wantsJSON(rest) {
			return writeExecErrorJSON(stdout, name, "bad_request", err.Error())
		}
		return fail(stderr, err)
	}
	if input != execInputArgs {
		command, err = readStdinCommand(stdin, input)
		if err != nil {
			if asJSON {
				return writeExecErrorJSON(stdout, name, "bad_request", err.Error())
			}
			return fail(stderr, err)
		}
	}
	return execCommandKeyed(d, p, command, asJSON, runKey, stdout, stderr)
}

func wantsJSON(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false // everything after -- is the remote command, not our flags
		}
		if arg == "--json" {
			return true
		}
	}
	return false
}

func writeExecErrorJSON(stdout io.Writer, name, kind, message string) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"connection": name,
		"exit_code":  1,
		"stdout":     "",
		"stderr":     message,
		"highlights": []string{},
		"error_kind": kind,
		"running":    false,
		"run_id":     "",
		"ok":         false,
	})
	return 1
}

// interactiveConnect opens a live shell directly, not through the broker.
// An interactive session is naturally one long-lived connection.
// It returns an error only when the connection could not be established; a
// session that opens and then ends (even with a non-zero shell code) returns
// a nil error so the caller can quietly return to the home screen.
func interactiveConnect(d deps, name string, stderr io.Writer) (int, error) {
	state, ok, err := loadConnectionState(d, name)
	if err != nil {
		return 1, err
	}
	if !ok {
		return 1, fmt.Errorf("unknown connection %q", name)
	}
	if state.authErr != nil {
		return 1, state.authErr
	}
	p := state.profile
	conn, err := sshconn.Dial(p, sshconn.DialOptions{
		Password:     state.secret.Password,
		Passphrase:   state.secret.Passphrase,
		AllowNewHost: true,
		Prompt:       hostKeyPrompt(stderr),
		JumpHosts:    state.jumps,
	})
	if err != nil {
		return 1, friendlyDialError(err)
	}
	defer conn.Close()

	connectBanner(stderr, p)
	start := time.Now()
	code, err := conn.Interactive()
	if err != nil {
		return 1, err
	}
	disconnectBanner(stderr, p)
	if err := d.log.Append(audit.Entry{
		StartedAt: start, FinishedAt: time.Now(),
		Profile: p.Name, Target: p.Target,
		Command: "<interactive>", ExitCode: code,
		DurationMS: time.Since(start).Milliseconds(),
		Status:     "completed",
	}); err != nil {
		fmt.Fprintln(stderr, "corv warning: local command history could not be written")
	}
	return code, nil
}

// openInteractive looks up name and opens a live shell. Used by the TUI manager
// loop; it returns an error only when the connection could not be established.
func openInteractive(d deps, name string, stderr io.Writer) error {
	_, err := interactiveConnect(d, name, stderr)
	return err
}

// Brand colours for the interactive session banner - the violet (256-colour
// 99) matches the TUI accent.
const (
	cViolet = "\x1b[38;5;99m"
	cDim    = "\x1b[2m"
	cReset  = "\x1b[0m"
)

// connectBanner and disconnectBanner identify interactive session boundaries.
// Both are suppressed when stdout is not a terminal.
func connectBanner(w io.Writer, p profile.Profile) {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return
	}
	fmt.Fprintln(w, cViolet+"corv"+cReset+cDim+" connected to "+cReset+
		cViolet+p.Name+cReset+"  "+cDim+p.Target+cReset)
}

func disconnectBanner(w io.Writer, p profile.Profile) {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return
	}
	fmt.Fprintln(w, cViolet+"corv"+cReset+cDim+" disconnected from "+p.Name+cReset)
}

// execCommand runs a command through the broker so the connection is reused.
func execCommand(d deps, p profile.Profile, command []string, asJSON bool, stdout, stderr io.Writer) int {
	return execCommandKeyed(d, p, command, asJSON, "", stdout, stderr)
}

func execCommandKeyed(d deps, p profile.Profile, command []string, asJSON bool, runKey string, stdout, stderr io.Writer) int {
	self, err := executablePath()
	if err != nil {
		if asJSON {
			return writeExecErrorJSON(stdout, p.Name, "local_error", err.Error())
		}
		return fail(stderr, err)
	}
	resp, err := newCommandBroker(self).ExecKeyed(p.Name, command, runKey)
	if err != nil {
		if asJSON {
			return writeExecErrorJSON(stdout, p.Name, "disconnected", fmt.Sprintf("broker: %v", err))
		}
		return fail(stderr, fmt.Errorf("broker: %w", err))
	}

	status := "completed"
	if resp.Running {
		status = "running"
	} else if resp.RunID != "" && !resp.RunMetadata && resp.Kind != "" {
		status = "pending"
	}
	if err := d.log.Append(audit.Entry{
		StartedAt: time.Now(), FinishedAt: time.Now(),
		Profile: p.Name, Target: p.Target,
		Command: commandForLog(command), ExitCode: resp.ExitCode,
		DurationMS: resp.DurationMS,
		Error:      resp.Kind,
		RunID:      resp.RunID,
		Status:     status,
	}); err != nil {
		resp.Highlights = append(resp.Highlights, "local command history could not be written")
	}

	code := exitCodeFor(resp)

	if asJSON {
		highlights := resp.Highlights
		if highlights == nil {
			highlights = []string{}
		}
		// The remote command's stdout and stderr are captured together,
		// interleaved in order, in resp.Stdout. The JSON stderr field carries
		// Corv-level error text (transport/setup failures), not the remote
		// command's own stderr - so a failed run still reports a message, not
		// just an error_kind.
		errText := resp.Stderr
		if errText == "" {
			errText = resp.Error
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		// exit_code mirrors the process exit code: the remote exit on success,
		// 75 while running, and nonzero for a transport/setup failure that never
		// produced a remote exit (so a failure is never reported as exit_code 0).
		payload := map[string]any{
			"connection": p.Name,
			"exit_code":  code,
			"stdout":     resp.Stdout,
			"stderr":     errText,
			"highlights": highlights,
			"error_kind": resp.Kind,
			"running":    resp.Running,
			"run_id":     resp.RunID,
			"ok":         resp.OK,
		}
		addOutputMetadata(payload, resp)
		_ = enc.Encode(payload)
		return code
	}

	io.WriteString(stdout, resp.Stdout)
	io.WriteString(stderr, resp.Stderr)
	// Surface notable lines even on exit-0 so warnings are never hidden by bounding.
	for _, h := range resp.Highlights {
		fmt.Fprintf(stderr, "corv warning: %s\n", h)
	}
	if !resp.OK && resp.ExitCode == 0 {
		// Transport/setup failure, not a remote non-zero exit.
		msg := resp.Error
		if msg == "" {
			msg = "command failed"
		}
		fmt.Fprintf(stderr, "corv: [%s] %s\n", resp.Kind, msg)
	}
	if resp.Running {
		fmt.Fprintf(stdout, "running: %s, run %s (re-run the same command to keep watching)\n", formatDuration(resp.DurationMS), resp.RunID)
	}
	return code
}

// exitCodeFor maps a broker response to a process exit code.
// Returns the remote exit code when one is available, 75 while still running,
// or 1 for a transport failure with no remote code.
func exitCodeFor(resp broker.Response) int {
	if resp.Running {
		return 75
	}
	if resp.OK {
		return resp.ExitCode
	}
	if resp.ExitCode != 0 {
		return resp.ExitCode
	}
	return 1
}

// hostKeyPrompt returns a callback that asks the user to verify an unknown
// host key, matching OpenSSH behaviour on first connect.
func hostKeyPrompt(w io.Writer) func(host, fp string) bool {
	return func(host, fp string) bool {
		fmt.Fprintf(w, "The authenticity of host '%s' can't be established.\n", host)
		fmt.Fprintf(w, "Key fingerprint is %s\n", fp)
		fmt.Fprint(w, "Continue connecting (y/n)? ")
		ok := readYesNo()
		if ok {
			fmt.Fprintln(w, "y")
		} else {
			fmt.Fprintln(w, "n")
		}
		return ok
	}
}

// readYesNo reads a single y/n keypress in raw mode. This works even right after
// the TUI releases the console: it may leave line-input mode off, so a cooked
// line read would never see Enter (the same reason a plain prompt would hang).
func readYesNo() bool {
	fd := int(os.Stdin.Fd())
	if oldState, err := term.MakeRaw(fd); err == nil {
		defer func() { _ = term.Restore(fd, oldState) }()
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				return false
			}
			switch buf[0] {
			case 'y', 'Y':
				return true
			case 'n', 'N', 3, 27: // n, Ctrl-C, Esc
				return false
			}
		}
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "yes" || answer == "y"
}

func friendlyDialError(err error) error {
	var hk *sshconn.HostKeyError
	if errors.As(err, &hk) {
		if hk.Changed {
			return fmt.Errorf("host key for %s has CHANGED - possible man-in-the-middle; refusing. If this is expected, remove the old entry from ~/.ssh/known_hosts", hk.Host)
		}
		return fmt.Errorf("host key for %s was not verified", hk.Host)
	}
	return err
}

func vaultSecret(d deps, p profile.Profile) (vault.Secret, error) {
	if p.SecretRef == "" {
		return vault.Secret{}, nil
	}
	secret, ok, err := d.secrets.Get(p.SecretRef)
	if err != nil {
		return vault.Secret{}, fmt.Errorf("read stored credentials for %q: %w", p.Name, err)
	}
	if !ok {
		return vault.Secret{}, fmt.Errorf("stored credentials for %q were not found", p.Name)
	}
	return secret, nil
}

func (d deps) jumpSecret(ref string) (password, passphrase string, err error) {
	secret, ok, err := d.secrets.Get(ref)
	if err != nil {
		return "", "", fmt.Errorf("read stored jump credentials %q: %w", ref, err)
	}
	if !ok {
		return "", "", fmt.Errorf("stored jump credentials %q were not found", ref)
	}
	return secret.Password, secret.Passphrase, nil
}

type connectionState struct {
	profile profile.Profile
	jumps   []sshconn.JumpHost
	secret  vault.Secret
	authErr error
}

type connectionStateError struct {
	stage string
	kind  string
	err   error
}

func (e *connectionStateError) Error() string { return e.err.Error() }
func (e *connectionStateError) Unwrap() error { return e.err }

func loadConnectionState(d deps, name string) (connectionState, bool, error) {
	var state connectionState
	var found bool
	err := statelock.WithLock(func() error {
		reg, err := d.store.Load()
		if err != nil {
			return &connectionStateError{stage: "local", kind: "local_error", err: err}
		}
		p, ok := reg.Get(name)
		if !ok {
			return nil
		}
		found = true
		jumps, err := sshconn.ParseJumpChain(p.ProxyJump)
		if err != nil {
			return &connectionStateError{
				stage: "jump",
				kind:  "bad_request",
				err:   fmt.Errorf("invalid proxy jump %q: %w", p.ProxyJump, err),
			}
		}
		if err := sshconn.EnrichJumpChain(jumps, reg, nil); err != nil {
			return &connectionStateError{stage: "jump", kind: "bad_request", err: err}
		}
		state = connectionState{profile: p, jumps: jumps}
		state.secret, state.authErr = vaultSecret(d, p)
		if state.authErr == nil {
			state.authErr = sshconn.EnrichJumpChain(state.jumps, reg, d.jumpSecret)
		}
		return nil
	})
	return state, found, err
}

type execInput uint8

const (
	execInputArgs execInput = iota
	execInputStdin
	execInputStdinBase64
)

func parseExec(args []string) (command []string, asJSON bool, input execInput, runKey string, err error) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			asJSON = true
		case "--stdin":
			if input != execInputArgs {
				return nil, false, execInputArgs, "", errors.New("--stdin cannot be combined with another input mode")
			}
			if command != nil {
				return nil, false, execInputArgs, "", errors.New("--stdin cannot be combined with -- <command>")
			}
			input = execInputStdin
		case "--stdin-base64":
			if input != execInputArgs {
				return nil, false, execInputArgs, "", errors.New("--stdin-base64 cannot be combined with another input mode")
			}
			if command != nil {
				return nil, false, execInputArgs, "", errors.New("--stdin-base64 cannot be combined with -- <command>")
			}
			input = execInputStdinBase64
		case "--run-key":
			i++
			if i >= len(args) {
				return nil, asJSON, execInputArgs, "", errors.New("--run-key requires a value")
			}
			if runKey != "" {
				return nil, asJSON, execInputArgs, "", errors.New("--run-key may be specified only once")
			}
			runKey = args[i]
			if !validRunKeyArg(runKey) {
				return nil, asJSON, execInputArgs, "", errors.New("run key must be 1-128 characters using letters, numbers, '.', '_', ':', or '-'")
			}
		case "--":
			if input != execInputArgs {
				return nil, false, execInputArgs, "", errors.New("stdin input cannot be combined with -- <command>")
			}
			command = args[i+1:]
			if len(command) == 0 {
				return nil, false, execInputArgs, "", errors.New("-- requires a command")
			}
			return command, asJSON, execInputArgs, runKey, nil
		default:
			return nil, false, execInputArgs, "", fmt.Errorf("unexpected argument %q; use: corv <name> [--json] [--run-key KEY] (--stdin | --stdin-base64 | -- <command>)", args[i])
		}
	}
	if input != execInputArgs {
		return nil, asJSON, input, runKey, nil
	}
	return nil, false, execInputArgs, "", errors.New("usage: corv <name> [--json] [--run-key KEY] (--stdin | --stdin-base64 | -- <command>)")
}

func validRunKeyArg(key string) bool {
	if len(key) < 1 || len(key) > 128 {
		return false
	}
	for _, r := range key {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == ':' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func readStdinCommand(stdin io.Reader, input execInput) ([]string, error) {
	const (
		maxCommandBytes = 8 * 1024 * 1024
		maxEncodedBytes = 12 * 1024 * 1024
	)
	limit := maxCommandBytes
	if input == execInputStdinBase64 {
		limit = maxEncodedBytes
	}
	data, err := io.ReadAll(io.LimitReader(stdin, int64(limit+1)))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("stdin command exceeds the %d MiB limit", maxCommandBytes/(1024*1024))
	}
	if input == execInputStdinBase64 {
		data, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("--stdin-base64 requires valid base64: %w", err)
		}
		if !utf8.Valid(data) {
			return nil, errors.New("--stdin-base64 decoded data is not valid UTF-8")
		}
		if len(data) > maxCommandBytes {
			return nil, fmt.Errorf("decoded stdin command exceeds the %d MiB limit", maxCommandBytes/(1024*1024))
		}
	}
	if input == execInputStdin && !utf8.Valid(data) {
		return nil, errors.New("--stdin input is not valid UTF-8 " +
			"(on Windows PowerShell this usually means the pipe re-encoded it; " +
			"use --stdin-base64 with UTF-8 base64 instead)")
	}
	command := string(data)
	if strings.TrimSpace(command) == "" {
		return nil, errors.New("stdin input requires a non-empty command")
	}
	return []string{command}, nil
}

func commandForLog(command []string) string {
	if len(command) == 0 {
		return "<interactive>"
	}
	return sshconn.CommandString(command)
}

func isInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func formatDuration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return (time.Duration(ms) * time.Millisecond).Round(time.Second).String()
}
