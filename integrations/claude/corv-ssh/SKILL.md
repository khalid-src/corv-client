---
name: corv-ssh
description: Run commands on remote machines over SSH via the `corv` CLI (a local SSH client). Use when the user asks to run, check, deploy, restart, or inspect something on a named server/host/VM, or mentions SSH or remote execution.
---

# Running remote commands with Corv

Corv is a local SSH client for running commands on remote machines. Machines are
saved by name; run commands by name and never handle credentials directly.

## Why Corv / when to use it

Use Corv when work must happen on a saved remote machine. Connections are kept
warm and reused, so running several focused commands against one host is cheap;
do not avoid useful round trips just to reduce SSH setup. Saved SSH credentials
remain in the local vault and never pass through the model. Command output is
structured and bounded, so a large build or installation log cannot consume
the entire context; query the retained log with `corv output <run-id> [pattern]`
when needed.
Detached jobs continue on the remote machine if the client connection drops.

## Discover

Use `corv list` to show saved connection names. Never guess a name; list first.
Do not run `corv list --full`, `corv doctor --full`, `corv test <name> --full`,
or `corv status --full` unless the user explicitly asks; those modes show local
connection details.

Use `corv test <name> --json` to diagnose a connection without running a remote
command. It reports DNS, TCP, jump, handshake, host-key, and authentication
stages with a stable `error_kind`. Use `corv status --json` to inspect warm
connections and running-job counts without starting the broker.

## Run

For simple commands:

```bash
corv <name> --json -- <command>
```

Parse the JSON fields: `exit_code`, `stdout`, `stderr`, `highlights`,
`error_kind`, `running`, `run_id`, `ok`, plus the output-size fields when
present. The process exit code mirrors the remote command's exit code. `stdout`
holds the command's combined stdout and stderr (in order); the `stderr` field
carries Corv-level errors only, so judge success by `ok` and `exit_code`.

Agent-facing output is always bounded. Large responses preserve their beginning
and end with a `... N line(s) hidden ...` marker. Corv retains up to 20 MiB per
run; for a larger log it keeps the first 4 MiB and the final section with an
omission marker. `corv output <run-id> [pattern]` returns a bounded view and can
filter relevant lines before applying the output budget. `truncated` means the
retained log omitted bytes; `output_truncated` means the returned view was
bounded. `original_bytes`, `saved_bytes`, and `returned_bytes` provide exact
sizes when available.

For any non-trivial script, nested quoting, or heredoc-like content, prefer
UTF-8 base64 over stdin.

### Windows / PowerShell

PowerShell callers should use:

```powershell
$b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(@'
set -eu
echo "build complete"
'@)); $b64 | corv <name> --json --stdin-base64
```

This preserves the command bytes exactly, including non-ASCII UTF-8 text. For
plain `--stdin` with non-ASCII text in PowerShell, first set
`$OutputEncoding=[Text.UTF8Encoding]::new()`.

After `--`: a single argument runs as a remote shell line
(`corv web -- "cd /app && git pull"`); multiple arguments are passed as a
preserved argument vector (`corv web -- sh -lc "cd /app && make"`).

## Rules

- Never put passwords, private keys, API tokens, bootstrap tokens, bearer tokens,
  or other secrets on the command line. Corv command history records command
  lines.
- Shell state does NOT persist between commands; combine with `&&`
  (e.g. `cd /app && make`).
- For non-trivial commands, encode UTF-8 command text as base64 and use
  `corv <name> --json --stdin-base64`.
- Do not run bare `corv` (the interactive TUI); it needs a real terminal.

## Long-running commands

A command that finishes within the wait window (~60s by default) returns
synchronously. `CORV_WAIT` sets that window per invocation (it is read from the
command's environment), as bare seconds (`30`) or a Go duration (`500ms`, `2m`).
Longer commands return exit code `75`, a `run_id`, and partial
output. To follow a detached run, poll `corv output <run-id>`; it checks the run
and finalizes the retained log once complete. Prefer this over re-running the
command: re-running attaches only when the command string is byte-for-byte
identical, so any difference would start a second run (and re-execute a
side-effecting command).

`corv output <run-id>` exits `75` while the run is still active, with the
remote exit code when it is complete, and `1` for a Corv retrieval/tool error.
Its process exit code and JSON `exit_code` field always agree.

Remote command execution requires a POSIX shell and is not supported against
Windows OpenSSH servers.

## Errors

When `ok` is false, `error_kind` is one of: `auth_failed`, `unknown_host`,
`unknown_connection`, `bad_request`, `local_error`, `unreachable`, `host_key`,
`timeout`, `disconnected`, `resource_exhausted`, `ssh_error`.

## Manage connections

Only manage connections when the user asks:

- `corv add <name> <user@host> [--port N] [--key PATH] [--jump user@bastion]`
- `corv import [path]`
- `corv rm <name>`
- `corv disconnect <name>`
- `corv log [name]`
- `corv doctor [name]`
- `corv test <name>`
- `corv status`

If a command fails with `error_kind: local_error` about stored credentials, do
not run `corv vault reset` yourself. It deletes stored passwords and key
passphrases. Tell the user about the error and let them decide whether to run
the recovery command.
