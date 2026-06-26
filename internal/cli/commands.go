package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/khalid-src/corv-client/internal/audit"
	"github.com/khalid-src/corv-client/internal/broker"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/sshconn"
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

	ref := "profile:" + p.Name
	reg, err := d.store.Load()
	if err != nil {
		return fail(stderr, err)
	}
	if err := reg.Set(p); err != nil {
		return fail(stderr, err)
	}

	if p.IdentityFile != "" {
		if passphrase := readSecret(stdin, stdout, "Key passphrase (leave empty for unencrypted key or agent auth): "); passphrase != "" {
			if err := d.secrets.Set(ref, vault.Secret{Passphrase: passphrase}); err != nil {
				return fail(stderr, err)
			}
			p.SecretRef = ref
		}
	} else {
		// Password is read without echo and kept only in the encrypted vault.
		if password := readSecret(stdin, stdout, "Password (leave empty for key or agent auth): "); password != "" {
			if err := d.secrets.Set(ref, vault.Secret{Password: password}); err != nil {
				return fail(stderr, err)
			}
			p.SecretRef = ref
		}
	}

	if err := reg.Set(p); err != nil {
		return fail(stderr, err)
	}
	if err := d.store.Save(reg); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "added %s -> %s\n", p.Name, p.Target)
	return 0
}

// readSecret reads a secret without echo from a terminal, or a single line
// from a pipe when input is not a terminal (for scripted setup).
func readSecret(stdin io.Reader, stdout io.Writer, prompt string) string {
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(stdout, prompt)
		b, _ := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(stdout)
		return strings.TrimSpace(string(b))
	}
	sc := bufio.NewScanner(stdin)
	if sc.Scan() {
		return strings.TrimSpace(sc.Text())
	}
	return ""
}

// reservedCommand reports whether name collides with a CLI subcommand, which
// would make the saved connection unreachable via `corv <name>`.
func reservedCommand(name string) bool {
	switch name {
	case "add", "import", "list", "ls", "rm", "remove", "disconnect", "close",
		"output", "log", "doctor", "help", "version", "__broker",
		"update", "upgrade", "uninstall":
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
	reg, err := d.store.Load()
	if err != nil {
		return fail(stderr, err)
	}
	added, err := importInto(d, &reg, imported, stderr)
	if err != nil {
		return fail(stderr, err)
	}
	if err := d.store.Save(reg); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "imported %d connection(s)\n", added)
	return 0
}

// importInto merges imported connections into reg, storing secrets in the vault.
// Existing connections are skipped so import is safe to re-run.
// Shared by the CLI and TUI import flows.
func importInto(d deps, reg *profile.Registry, imported []profile.Imported, stderr io.Writer) (int, error) {
	added := 0
	for _, im := range imported {
		p := im.Profile
		if _, exists := reg.Get(p.Name); exists {
			continue
		}
		if p.IdentityFile == "" && im.KeyMaterial != "" {
			keyPath, err := profile.WriteIdentityFile(p.Name, im.KeyMaterial)
			if err != nil {
				fmt.Fprintf(stderr, "corv: skip %s: %v\n", p.Name, err)
				continue
			}
			p.IdentityFile = keyPath
		}
		if err := reg.Set(p); err != nil {
			fmt.Fprintf(stderr, "corv: skip %s: %v\n", p.Name, err)
			continue
		}
		if im.Password != "" || im.Passphrase != "" {
			ref := "profile:" + p.Name
			if err := d.secrets.Set(ref, vault.Secret{Password: im.Password, Passphrase: im.Passphrase}); err != nil {
				return added, err
			}
			p.SecretRef = ref
		}
		if err := reg.Set(p); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
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
	// printed to whoever (or whatever) ran the command - an AI agent only needs
	// the name to connect. `--full` shows the details for a human at the keyboard.
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
	reg, err := d.store.Load()
	if err != nil {
		return fail(stderr, err)
	}
	p, ok := reg.Get(args[0])
	if !ok {
		return fail(stderr, fmt.Errorf("unknown connection %q", args[0]))
	}
	reg.Remove(args[0])
	if err := d.store.Save(reg); err != nil {
		return fail(stderr, err)
	}
	if p.SecretRef != "" {
		_ = d.secrets.Delete(p.SecretRef)
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
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--clear":
			clear = true
		case "--tail", "-n":
			i++
			if i >= len(args) {
				return fail(stderr, errors.New("--tail requires a value"))
			}
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 0 {
				return fail(stderr, fmt.Errorf("invalid tail value: %s", args[i]))
			}
			tail = n
		default:
			if name != "" {
				return fail(stderr, fmt.Errorf("unexpected argument: %s", args[i]))
			}
			name = args[i]
		}
	}

	if clear {
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
		return fail(stderr, err)
	}
	for _, e := range entries {
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n",
			e.StartedAt.Local().Format(time.RFC3339), e.Profile, logStatus(e.ExitCode, e.Error), audit.OneLine(e.Command))
	}
	return 0
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
			return writeOutputJSON(stdout, broker.Response{OK: false, RunID: runID, Error: err.Error()})
		}
		return fail(stderr, err)
	}
	self, err := os.Executable()
	if err != nil {
		if asJSON {
			return writeOutputJSON(stdout, broker.Response{OK: false, RunID: runID, Error: err.Error()})
		}
		return fail(stderr, err)
	}
	resp, err := broker.NewClient(self).Output(runID, pattern)
	if err != nil {
		if asJSON {
			return writeOutputJSON(stdout, broker.Response{OK: false, RunID: runID, Error: fmt.Sprintf("broker: %v", err)})
		}
		return fail(stderr, fmt.Errorf("broker: %w", err))
	}
	if asJSON {
		return writeOutputJSON(stdout, resp)
	}
	if !resp.OK && !resp.RunMetadata {
		return fail(stderr, errors.New(resp.Error))
	}
	io.WriteString(stdout, resp.Stdout)
	for _, h := range resp.Highlights {
		fmt.Fprintf(stderr, "corv warning: %s\n", h)
	}
	if resp.RunMetadata && resp.ExitCode != 0 {
		return resp.ExitCode
	}
	return 0
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
		"ok":         resp.OK,
	}
	if resp.Error != "" {
		payload["error"] = resp.Error
	}
	if resp.Kind != "" {
		payload["error_kind"] = resp.Kind
	}
	if resp.RunMetadata {
		payload["connection"] = resp.Connection
		payload["exit_code"] = resp.ExitCode
		payload["running"] = false
		payload["started_at"] = resp.StartedAt
		payload["finished_at"] = resp.FinishedAt
		payload["truncated"] = resp.Truncated
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
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
	client := broker.NewClient(self)

	// Running() only pings; List() goes through ensureRunning() and could spawn
	// the broker. Gate List() behind Running() so a status check never starts it.
	var held []broker.HeldInfo
	if client.Running() {
		held, _ = client.List()
		fmt.Fprintf(stdout, "broker:           running (%d held connection(s))\n", len(held))
	} else {
		fmt.Fprintln(stdout, "broker:           not running (starts on first command)")
	}
	fmt.Fprintf(stdout, "config:           %s\n", presentLabel(d.paths.ConfigFile))
	fmt.Fprintf(stdout, "audit log:        %s\n", presentLabel(d.paths.AuditFile))
	fmt.Fprintln(stdout, "remote footprint: none")

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
		return 0
	}

	reg, err := d.store.Load()
	if err != nil {
		return fail(stderr, err)
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

func presentLabel(path string) string {
	if _, err := os.Stat(path); err == nil {
		return "present"
	}
	return "missing"
}
