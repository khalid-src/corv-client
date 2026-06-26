// Package cli wires Corv together: parses the command line, loads local
// state, and dispatches to the interactive UI (TUI), the SSH backend,
// and the vault.
package cli

import (
	"fmt"
	"io"

	"github.com/khalid-src/corv-client/internal/audit"
	"github.com/khalid-src/corv-client/internal/broker"
	"github.com/khalid-src/corv-client/internal/paths"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/vault"
	"github.com/khalid-src/corv-client/internal/version"
)

const usage = `corv - the SSH client for AI agents and humans

Usage:
  corv                     open the interactive UI (TUI)
  corv <name>              connect to a saved machine
  corv <name> -- <cmd>     run a command on a saved machine
  corv <name> --stdin      read a remote shell command from stdin
  corv <name> --stdin-base64
                           read a base64-encoded UTF-8 command from stdin
  corv add <name> <user@host> [--port N] [--key PATH] [--jump user@bastion]
  corv import [path]       import hosts from an SSH config
  corv list                list saved connection names (--full for details)
  corv rm <name>           remove a saved connection
  corv disconnect <name>   drop the held-open connection
  corv output <run-id>     show a completed async run log (--json for tools)
  corv log [name]          show recent command history (--clear to wipe it)
  corv doctor [name]       check the local setup (--full for details)
  corv update              download and install the latest release
  corv uninstall           remove corv (--purge also deletes saved data)

Define connections once (or import them). After that, AI agents and humans
just use the name: corv <name>. Stored credentials stay local and never
appear in the command line, prompts, or logs shown to an agent.

Commands after --: a single argument is run as a remote shell command line
(corv srv -- "cd /app && make"); multiple arguments are passed as a preserved
argument vector (corv srv -- sh -lc "cd /app && make"). Either way the remote
runs exactly what you intended. Use --stdin-base64 for complex shell text that
must bypass local quoting and PowerShell pipe encoding.`

// deps bundles the local state every command needs.
type deps struct {
	store   *profile.Store
	secrets *vault.Store
	log     *audit.Log
	paths   paths.Paths
}

func loadDeps() (deps, error) {
	p, err := paths.Default()
	if err != nil {
		return deps{}, err
	}
	secrets := vault.New(p.VaultFile, p.VaultKey)
	return deps{
		store:   profile.NewStore(p.ConfigFile, secrets),
		secrets: secrets,
		log:     audit.NewLog(p.AuditFile),
		paths:   p,
	}, nil
}

// Run is the program entry point. It returns a process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cleanupOldExecutable()

	if len(args) > 0 {
		switch args[0] {
		case "help", "--help", "-h":
			fmt.Fprintln(stdout, usage)
			return 0
		case "version", "--version":
			fmt.Fprintln(stdout, "corv "+version.Version)
			return 0
		case "__broker":
			if err := broker.Serve(); err != nil {
				return fail(stderr, err)
			}
			return 0
		case "update", "upgrade":
			return cmdUpdate(args[1:], stdout, stderr)
		case "uninstall":
			return cmdUninstall(args[1:], stdout, stderr)
		}
	}

	d, err := loadDeps()
	if err != nil {
		return fail(stderr, err)
	}

	if len(args) == 0 {
		return runManager(d, stdin, stdout, stderr)
	}

	switch args[0] {
	case "add":
		return cmdAdd(d, args[1:], stdin, stdout, stderr)
	case "import":
		return cmdImport(d, args[1:], stdout, stderr)
	case "list", "ls":
		return cmdList(d, args[1:], stdout, stderr)
	case "rm", "remove":
		return cmdRemove(d, args[1:], stdout, stderr)
	case "disconnect", "close":
		return cmdDisconnect(d, args[1:], stdout, stderr)
	case "output":
		return cmdOutput(args[1:], stdout, stderr)
	case "log":
		return cmdLog(d, args[1:], stdout, stderr)
	case "doctor":
		return cmdDoctor(d, args[1:], stdout, stderr)
	default:
		return cmdConnect(d, args, stdin, stdout, stderr)
	}
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "corv: %v\n", err)
	return 1
}
