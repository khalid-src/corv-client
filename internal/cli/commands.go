package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"golang.org/x/term"

	"github.com/khalid-src/corv-client/internal/audit"
	"github.com/khalid-src/corv-client/internal/broker"
	"github.com/khalid-src/corv-client/internal/importstate"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/sshconn"
	"github.com/khalid-src/corv-client/internal/statelock"
	"github.com/khalid-src/corv-client/internal/vault"
)

func cmdAdd(d deps, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		return fail(stderr, errors.New("usage: corv add <name> <user@host> [--port N] [--key PATH]"))
	}
	if reservedCommand(args[0]) {
		return fail(stderr, fmt.Errorf("%q is a reserved command name; pick another (it would be unreachable as `corv %s`)", args[0], args[0]))
	}
	p := profile.Profile{Name: args[0], Target: args[1]}
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--port", "-p":
			i++
			if i >= len(args) {
				return fail(stderr, errors.New("--port requires a value"))
			}
			port, err := strconv.Atoi(args[i])
			if err != nil || port <= 0 || port > 65535 {
				return fail(stderr, fmt.Errorf("invalid port: %s", args[i]))
			}
			p.Port = port
		case "--key", "--identity", "-i":
			i++
			if i >= len(args) {
				return fail(stderr, errors.New("--key requires a path"))
			}
			p.IdentityFile = args[i]
		case "--jump", "-J":
			i++
			if i >= len(args) {
				return fail(stderr, errors.New("--jump requires a host (user@bastion[,user@bastion2])"))
			}
			if _, err := sshconn.ParseJumpChain(args[i]); err != nil {
				return fail(stderr, fmt.Errorf("invalid --jump: %w", err))
			}
			p.ProxyJump = args[i]
		default:
			return fail(stderr, fmt.Errorf("unknown option: %s", args[i]))
		}
	}

	validation := profile.Registry{}
	if err := validation.Set(p); err != nil {
		return fail(stderr, err)
	}

	var secret vault.Secret
	hasSecret := false
	if p.IdentityFile != "" {
		if passphrase := readSecret(stdin, stdout, "Key passphrase (blank keeps a saved passphrase; new connections use an unencrypted key/agent): "); passphrase != "" {
			secret.Passphrase = passphrase
			hasSecret = true
		}
	} else {
		// Password is read without echo and kept only in the encrypted vault.
		if password := readSecret(stdin, stdout, "Password (blank keeps a saved password; new connections use key/agent auth): "); password != "" {
			secret.Password = password
			hasSecret = true
		}
	}

	replaced := false
	err := statelock.WithLock(func() error {
		reg, err := d.store.Load()
		if err != nil {
			return err
		}
		existing, exists := reg.Get(p.Name)
		replaced = exists
		if exists && !hasSecret {
			p.SecretRef = existing.SecretRef
		}

		var newRef string
		if hasSecret {
			newRef, err = uniqueCredentialRef(p.Name)
			if err != nil {
				return err
			}
			if err := d.secrets.Set(newRef, secret); err != nil {
				return err
			}
			p.SecretRef = newRef
		}
		if err := reg.Set(p); err != nil {
			if newRef != "" {
				return errors.Join(err, d.secrets.Delete(newRef))
			}
			return err
		}
		if err := d.store.Save(reg); err != nil {
			if newRef != "" {
				return errors.Join(err, d.secrets.Delete(newRef))
			}
			return err
		}
		if exists && existing.SecretRef != "" && existing.SecretRef != p.SecretRef {
			if err := d.secrets.Delete(existing.SecretRef); err != nil {
				return fmt.Errorf("remove replaced credentials for %q: %w", p.Name, err)
			}
		}
		return nil
	})
	if err != nil {
		return fail(stderr, err)
	}
	verb := "added"
	if replaced {
		verb = "replaced"
	}
	fmt.Fprintf(stdout, "%s %s -> %s\n", verb, p.Name, p.Target)
	return 0
}

func uniqueCredentialRef(name string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate credential reference: %w", err)
	}
	return "profile:" + name + ":" + hex.EncodeToString(random), nil
}

// readSecret reads a secret without echo from a terminal, or a single line
// from a pipe when input is not a terminal (for scripted setup).
func readSecret(stdin io.Reader, stdout io.Writer, prompt string) string {
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(stdout, prompt)
		b, _ := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(stdout)
		return string(b)
	}
	sc := bufio.NewScanner(stdin)
	if sc.Scan() {
		return sc.Text()
	}
	return ""
}

// reservedCommand reports whether name collides with a CLI subcommand, which
// would make the saved connection unreachable via `corv <name>`.
func reservedCommand(name string) bool {
	switch name {
	case "add", "import", "list", "ls", "rm", "remove", "disconnect", "close",
		"output", "jobs", "log", "doctor", "test", "status", "vault", "help", "version",
		"__broker", "update", "upgrade", "uninstall":
		return true
	}
	return false
}

func cmdImport(d deps, args []string, stdout, stderr io.Writer) int {
	path := ""
	switch len(args) {
	case 0:
	case 1:
		path = profile.TrimPath(args[0])
	default:
		return fail(stderr, errors.New("usage: corv import [path-to-ssh-config-or-.csv]"))
	}

	imported, err := profile.Import(path)
	if err != nil {
		return fail(stderr, err)
	}
	result, err := importstate.Apply(d.store, d.secrets, imported)
	if err != nil {
		return fail(stderr, err)
	}
	for _, warning := range result.Warnings {
		fmt.Fprintf(stderr, "corv: %s\n", warning)
	}
	fmt.Fprintf(stdout, "imported %d connection(s)\n", result.Added)
	return 0
}

func cmdList(d deps, args []string, stdout, stderr io.Writer) int {
	full := false
	for _, a := range args {
		switch a {
		case "--full", "--details", "-l":
			full = true
		default:
			return fail(stderr, fmt.Errorf("unexpected argument: %s", a))
		}
	}

	reg, err := d.store.Load()
	if err != nil {
		return fail(stderr, err)
	}
	profiles := reg.List()
	if len(profiles) == 0 {
		fmt.Fprintln(stdout, "no connections saved (try `corv add` or `corv import`)")
		return 0
	}

	// Default: names only. Addresses, users and ports stay local and are never
	// printed to the caller - an agent only needs the name to connect.
	// `--full` shows the details for a human at the keyboard.
	if !full {
		for _, p := range profiles {
			fmt.Fprintln(stdout, p.Name)
		}
		return 0
	}

	for _, p := range profiles {
		port := 22
		if p.Port != 0 {
			port = p.Port
		}
		auth := "agent"
		if p.IdentityFile != "" {
			auth = "key"
		} else if p.SecretRef != "" {
			auth = "password"
		}
		jump := ""
		if p.ProxyJump != "" {
			jump = "via " + p.ProxyJump
		}
		fmt.Fprintf(stdout, "%-20s  %-32s  %-5d  %-8s  %s\n", p.Name, p.Target, port, auth, jump)
	}
	return 0
}

func cmdRemove(d deps, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		return fail(stderr, errors.New("usage: corv rm <name>"))
	}
	err := statelock.WithLock(func() error {
		reg, err := d.store.Load()
		if err != nil {
			return err
		}
		p, ok := reg.Get(args[0])
		if !ok {
			return fmt.Errorf("unknown connection %q", args[0])
		}
		reg.Remove(args[0])
		if err := d.store.Save(reg); err != nil {
			return err
		}
		if p.SecretRef != "" {
			if err := d.secrets.Delete(p.SecretRef); err != nil {
				return fmt.Errorf("remove stored credentials for %q: %w", args[0], err)
			}
		}
		return nil
	})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "removed %s\n", args[0])
	return 0
}

func cmdDisconnect(d deps, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		return fail(stderr, errors.New("usage: corv disconnect <name>"))
	}
	self, err := os.Executable()
	if err != nil {
		return fail(stderr, err)
	}
	if _, err := broker.NewClient(self).Close(args[0]); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "disconnected %s\n", args[0])
	return 0
}

func cmdLog(d deps, args []string, stdout, stderr io.Writer) int {
	name := ""
	tail := 50
	clear := false
	asJSON := hasArg(args, "--json")
	failLog := func(kind string, err error) int {
		if asJSON {
			return writeLogErrorJSON(stdout, kind, err)
		}
		return fail(stderr, err)
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--clear":
			clear = true
		case "--json":
		case "--tail", "-n":
			i++
			if i >= len(args) {
				return failLog("bad_request", errors.New("--tail requires a value"))
			}
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 0 {
				return failLog("bad_request", fmt.Errorf("invalid tail value: %s", args[i]))
			}
			tail = n
		default:
			if name != "" {
				return failLog("bad_request", fmt.Errorf("unexpected argument: %s", args[i]))
			}
			name = args[i]
		}
	}

	if clear {
		if asJSON {
			return failLog("bad_request", errors.New("--json cannot be combined with --clear"))
		}
		if name != "" {
			return fail(stderr, errors.New("--clear wipes the whole audit log; it can't be limited to one connection"))
		}
		if err := d.log.Clear(); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintln(stdout, "audit log cleared")
		return 0
	}

	entries, err := d.log.Read(name, tail)
	if err != nil {
		return failLog("local_error", err)
	}
	if asJSON {
		if entries == nil {
			entries = []audit.Entry{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			return fail(stderr, err)
		}
		return 0
	}
	for _, e := range entries {
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s",
			e.StartedAt.Local().Format(time.RFC3339), e.Profile, logStatus(e.ExitCode, e.Error), audit.OneLine(e.Command))
		if e.RunID != "" {
			fmt.Fprintf(stdout, "\trun=%s", e.RunID)
		}
		fmt.Fprintln(stdout)
	}
	return 0
}

func writeLogErrorJSON(w io.Writer, kind string, err error) int {
	entries := []audit.Entry{}
	payload := struct {
		OK        bool          `json:"ok"`
		Entries   []audit.Entry `json:"entries"`
		Error     string        `json:"error"`
		ErrorKind string        `json:"error_kind"`
	}{OK: false, Entries: entries, Error: err.Error(), ErrorKind: kind}
	_ = json.NewEncoder(w).Encode(payload)
	return 1
}

func logStatus(exitCode int, err string) string {
	if exitCode == 75 {
		return "running"
	}
	if exitCode != 0 || err != "" {
		return fmt.Sprintf("exit=%d", exitCode)
	}
	return "ok"
}

func cmdOutput(args []string, stdout, stderr io.Writer) int {
	asJSON, runID, pattern, err := parseOutputArgs(args)
	if err != nil {
		if asJSON {
			return writeOutputJSON(stdout, broker.Response{OK: false, RunID: runID, Error: err.Error(), Kind: "bad_request"})
		}
		return fail(stderr, err)
	}
	self, err := os.Executable()
	if err != nil {
		if asJSON {
			return writeOutputJSON(stdout, broker.Response{OK: false, RunID: runID, Error: err.Error(), Kind: "local_error"})
		}
		return fail(stderr, err)
	}
	resp, err := broker.NewClient(self).Output(runID, pattern)
	if err != nil {
		if asJSON {
			return writeOutputJSON(stdout, broker.Response{OK: false, RunID: runID, Error: fmt.Sprintf("broker: %v", err), Kind: "disconnected"})
		}
		return fail(stderr, fmt.Errorf("broker: %w", err))
	}
	if asJSON {
		return writeOutputJSON(stdout, resp)
	}
	return writeOutputPlain(stdout, stderr, resp)
}

func writeOutputPlain(stdout, stderr io.Writer, resp broker.Response) int {
	io.WriteString(stdout, resp.Stdout)
	for _, h := range resp.Highlights {
		fmt.Fprintf(stderr, "corv warning: %s\n", h)
	}
	if resp.Running {
		message := resp.Error
		if message == "" {
			message = fmt.Sprintf("run %s is still in progress", resp.RunID)
		}
		fmt.Fprintln(stderr, message)
		return 75
	}
	if !resp.OK && !resp.RunMetadata {
		return fail(stderr, errors.New(resp.Error))
	}
	return outputExitCode(resp)
}

func parseOutputArgs(args []string) (bool, string, string, error) {
	asJSON := false
	pos := make([]string, 0, 2)
	for _, arg := range args {
		if arg == "--json" {
			asJSON = true
			continue
		}
		pos = append(pos, arg)
	}
	if len(pos) < 1 || len(pos) > 2 {
		return asJSON, "", "", errors.New("usage: corv output [--json] <run-id> [pattern]")
	}
	pattern := ""
	if len(pos) == 2 {
		pattern = pos[1]
	}
	return asJSON, pos[0], pattern, nil
}

func writeOutputJSON(stdout io.Writer, resp broker.Response) int {
	highlights := resp.Highlights
	if highlights == nil {
		highlights = []string{}
	}
	payload := map[string]any{
		"run_id":     resp.RunID,
		"stdout":     resp.Stdout,
		"highlights": highlights,
		"error_kind": resp.Kind,
		"ok":         resp.OK,
		"running":    resp.Running,
		"exit_code":  outputExitCode(resp),
	}
	if resp.DurationMS > 0 {
		payload["duration_ms"] = resp.DurationMS
	}
	if resp.Error != "" {
		payload["error"] = resp.Error
	}
	if resp.RunMetadata {
		payload["connection"] = resp.Connection
		payload["started_at"] = resp.StartedAt
		payload["finished_at"] = resp.FinishedAt
		payload["truncated"] = resp.Truncated
	}
	addOutputMetadata(payload, resp)
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
	return outputExitCode(resp)
}

func addOutputMetadata(payload map[string]any, resp broker.Response) {
	if resp.Lossy {
		payload["lossy"] = true
	}
	if resp.RunMetadata || resp.ReturnedBytes > 0 || resp.Stdout != "" {
		payload["returned_bytes"] = resp.ReturnedBytes
	}
	if resp.RunMetadata || resp.OriginalBytes > 0 {
		payload["original_bytes"] = resp.OriginalBytes
	}
	if resp.RunMetadata || resp.SavedBytes > 0 {
		payload["saved_bytes"] = resp.SavedBytes
	}
	if resp.RunMetadata || resp.OutputTruncated {
		payload["output_truncated"] = resp.OutputTruncated
	}
	if resp.Truncated {
		payload["truncated"] = true
	}
}

func outputExitCode(resp broker.Response) int {
	if resp.Running {
		return 75
	}
	if resp.RunMetadata {
		return resp.ExitCode
	}
	if resp.OK {
		return 0
	}
	return 1
}

func cmdDoctor(d deps, args []string, stdout, stderr io.Writer) int {
	full := false
	name := ""
	for _, arg := range args {
		switch arg {
		case "--full", "--details", "-l":
			full = true
		default:
			if name != "" {
				return fail(stderr, fmt.Errorf("unexpected argument: %s", arg))
			}
			name = arg
		}
	}

	self, _ := os.Executable()
	client := newDoctorClient(self)

	var held []broker.HeldInfo
	running, connections, brokerErr := client.Status()
	brokerOK := brokerErr == nil
	if brokerErr != nil {
		fmt.Fprintf(stdout, "broker:           unavailable (%s)\n", doctorLocalError(brokerErr, full))
	} else if running {
		for _, connection := range connections {
			held = append(held, broker.HeldInfo{
				Name:   connection.Name,
				Target: connection.Target,
				IdleMS: connection.IdleMS,
			})
		}
		fmt.Fprintf(stdout, "broker:           running (%d held connection(s))\n", len(held))
	} else {
		fmt.Fprintln(stdout, "broker:           not running (starts on first command)")
	}
	configState, configOK := presentLabel(d.paths.ConfigFile, full)
	auditState, auditOK := presentLabel(d.paths.AuditFile, full)
	fmt.Fprintf(stdout, "config:           %s\n", configState)
	fmt.Fprintf(stdout, "audit log:        %s\n", auditState)
	fmt.Fprintln(stdout, "remote footprint: temporary files for detached runs only")

	reg, stateErr := d.store.LoadReadOnly()
	vaultOK := stateErr == nil
	if stateErr != nil {
		fmt.Fprintf(stdout, "vault:            unreadable (%s)\n", doctorVaultError(stateErr, full))
	} else {
		refs := make(map[string]struct{})
		for _, p := range reg.Profiles {
			if p.SecretRef != "" {
				refs[p.SecretRef] = struct{}{}
			}
		}
		if len(refs) == 0 {
			fmt.Fprintln(stdout, "vault:            not used (no stored credentials)")
		} else {
			for ref := range refs {
				_, ok, err := d.secrets.Get(ref)
				if err != nil {
					stateErr = err
					vaultOK = false
					break
				}
				if !ok {
					stateErr = errors.New("a saved connection refers to a credential that is missing")
					vaultOK = false
					break
				}
			}
			if vaultOK {
				fmt.Fprintln(stdout, "vault:            readable")
			} else {
				fmt.Fprintf(stdout, "vault:            unreadable (%s)\n", doctorVaultError(stateErr, full))
			}
		}
	}

	for _, h := range held {
		if full {
			fmt.Fprintf(stdout, "  held: %-20s %-30s idle %ds\n", h.Name, h.Target, h.IdleMS/1000)
			continue
		}
		fmt.Fprintf(stdout, "  held: %-20s idle %ds\n", h.Name, h.IdleMS/1000)
	}

	if full {
		fmt.Fprintf(stdout, "config path:      %s\n", d.paths.ConfigFile)
		fmt.Fprintf(stdout, "audit log path:   %s\n", d.paths.AuditFile)
	}

	if name == "" {
		if !vaultOK || !brokerOK || !configOK || !auditOK {
			return 1
		}
		return 0
	}

	if !vaultOK || !brokerOK || !configOK || !auditOK {
		return 1
	}
	p, ok := reg.Get(name)
	if !ok {
		return fail(stderr, fmt.Errorf("unknown connection %q", name))
	}
	state := "not connected"
	for _, h := range held {
		if h.Name == p.Name {
			state = "connected (held open)"
		}
	}
	if full {
		fmt.Fprintf(stdout, "\nconnection:       %s -> %s\n", p.Name, p.Target)
	} else {
		fmt.Fprintf(stdout, "\nconnection:       %s\n", p.Name)
	}
	fmt.Fprintf(stdout, "status:           %s\n", state)
	return 0
}

func doctorVaultError(err error, full bool) string {
	if full {
		return err.Error()
	}
	if errors.Is(err, vault.ErrKeyAccess) {
		return "the vault key is unavailable to this process context; use --full for details"
	}
	if errors.Is(err, profile.ErrConfigUnreadable) {
		return "the vault key is unavailable or encrypted local state is damaged; use --full for details"
	}
	return "stored local state could not be read; use --full for details"
}

func presentLabel(path string, full bool) (string, bool) {
	_, err := os.Stat(path)
	if err == nil {
		return "present", true
	}
	if errors.Is(err, os.ErrNotExist) {
		return "missing", true
	}
	return "unavailable (" + doctorLocalError(err, full) + ")", false
}

func doctorLocalError(err error, full bool) string {
	if full {
		return err.Error()
	}
	return "local state could not be inspected; use --full for details"
}
