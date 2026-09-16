# Changelog

All notable changes to Corv are documented here. Corv uses one changelog entry
per release tag.

## v1.1.1 - 2026-09-16

This patch release improves recovery and diagnostics for detached agent work
without changing saved connection, vault, or run-log formats.

### Added

- **`corv jobs`.** Lists active and recently retained runs by connection name,
  run ID, status, start time, and exit code, with structured JSON output.
- **`--run-key`.** A caller-supplied, profile-scoped key suppresses replay of a
  mutating command. Completed outcomes remain reusable for 24 hours; unresolved
  runs retain their key. A conflicting command or connection state fails
  explicitly instead of executing.
- **Structured audit history.** `corv log --json` exposes the existing audit
  entries, and plain history includes the run ID when one is present.

### Fixed

- Empty decorated section headings such as `=== FAILED UNITS ===` no longer
  appear as failure highlights; actual failure details remain highlighted.

- Clarified that `corv log --clear` erases the entire audit log, and that audit
  history currently has no automatic rotation or retention limit.
- Documented that replay protection is scoped to one local state directory and
  saved connection; separate clients do not share deduplication records.

- **Vault access failures are actionable.** Windows DPAPI and Unix keychain
  failures retain the underlying error while identifying unavailable user,
  profile, session, or keychain context.
- **Doctor checks encrypted state.** `corv doctor` verifies the connection store
  and referenced credentials without migrating state, starting the broker, or
  exposing detailed local information by default.
- **Running output is visible and bounded.** `corv output <run-id>` returns a
  recent-output snapshot while a detached process is active, without consuming
  the run's output offset or sending an unbounded log to the caller.
- **Stale runs no longer claim to be active.** Unverified old records are shown
  as `unknown`; an explicit output probe records missing remote state as
  `expired` without fabricating an exit code or completion timestamp. Expired
  run keys remain reserved to prevent an uncertain operation from executing
  twice.
- **Run-key outcomes survive every completion path.** Finalizing through
  `corv output`, restarting the broker, or retrying after a lost response does
  not discard the retained replay record. Nonzero exit codes are preserved in
  persisted job state.
- **Terminal-state persistence is fail-safe.** If completed job state cannot be
  saved, Corv retains the remote output and leaves the job pending for a safe
  finalization retry, returning a typed local error instead of success. Final
  state is committed only after the retained log is durable. A missing log does
  not erase a known remote exit status and is reported as `output_unavailable`.
- **Detached timing reflects execution.** New remote exit records preserve the
  command's execution duration, so delayed polling no longer inflates
  `duration_ms`. Existing run records remain readable.
- **Remote cleanup uses completion age.** A long-running job is not swept merely
  because it started more than 24 hours ago; new records are aged from their
  terminal exit time.
- **Lossy text conversion is disclosed.** JSON output sets `lossy: true` when
  invalid UTF-8 bytes must be replaced, and reassuring counts such as
  `0 failed` no longer appear as warning highlights.
- **Vault requirements are documented before failure.** Agent and operator
  guidance explains that the encrypted store requires the OS user profile and
  keychain context that created it.
- **Structured output failures remain typed.** `corv output --json` includes an
  `error_kind` for argument, local-state, broker, metadata, and finalization
  failures, and includes an empty value on success for a stable schema.
- **SSH config imports follow inclusion context.** Global directives and nested
  `Include` files retain OpenSSH first-value semantics. Imported keys,
  credentials, and profiles roll back together when the profile save fails.
- **Local diagnostics and IPC fail honestly.** Unix broker directories and
  sockets enforce owner-only permissions; doctor distinguishes inaccessible
  state from missing state; local history write failures are surfaced without
  changing the remote result.
- **Connection reads are transactionally consistent.** Interactive sessions and
  diagnostics cannot combine an old endpoint with newly replaced credentials.
  CLI replacements use fresh credential references, and missing referenced
  credentials fail consistently in every connection mode.
- **Broker replacement verifies process identity.** A reused operating-system
  process ID, including one from a legacy endpoint record, cannot block startup,
  and broker-log creation failures are reported.
- **Local history and keychain access are bounded.** Tail reads and completion
  checks avoid loading the full audit history, and OS keychain commands cannot
  block indefinitely.
- **Release inputs are reproducible.** Third-party actions are pinned to commit
  SHAs, and analysis tools use fixed module versions.
- **Build dependencies include current security fixes.** Release and CI builds
  use Go 1.26.8 and `golang.org/x/crypto` 0.56.0.
- **Detached script uploads are verified before launch.** Corv checks the exact
  streamed byte count, so an interrupted upload cannot execute a partial
  command.
- **Persisted run identity contains no offline credential verifier.**
  Vault-keyed fingerprints detect destination, route, and credential changes
  without making password guesses testable from `jobs.json`; existing records
  migrate when their saved connection is next resolved.
- **Exit code 75 is unambiguous in command history.** New entries record their
  lifecycle explicitly, so a remote command that genuinely exits with 75 is
  not mistaken for an unfinished run.
- **In-place updates are crash-durable.** Replacement binaries are synced
  before installation, and a failed Windows rollback is reported rather than
  hidden.

## v1.1 - 2026-07-23

A reliability and compatibility release with focused connection diagnostics.
Existing installs upgrade in place with `corv update`; saved connections and
secrets remain readable without an on-disk migration.

### Added

- **`corv test <name>`.** Checks DNS, TCP reachability, bastion routing, the SSH
  handshake, host-key trust, and authentication without running a remote
  command. Plain and structured JSON output identify the first failing stage;
  raw targets and addresses require `--full`.
- **`corv status`.** Reports warm broker connections, idle time, and active run
  counts without starting a stopped broker. Targets require `--full`.
- **`corv vault reset`.** Clears stored passwords and private-key passphrases
  while preserving saved connections. It refuses to guess when the encrypted
  connection store cannot be opened; `--all` explicitly removes local Corv
  connection and vault files. Externally provisioned OS keychain entries are
  not removed.
- **Deeper agent integration guidance.** The Codex and Claude instructions now
  explain when to use Corv, bounded output, connection reuse, detached jobs,
  diagnostics, and async output exit codes.

### Fixed

- **Agent-facing output is bounded end to end.** `corv output` no longer sends
  an entire retained log over IPC or into an agent context. Large retained logs
  preserve both the beginning and the end, and JSON reports exact original,
  saved, and returned byte counts.
- **Warm connections follow the current profile.** Changing a target, port,
  jump chain, identity, or stored credential invalidates the old connection and
  detached-job association before the next command.
- **Concurrent SSH work queues safely.** Per-connection channel limits and
  resource-exhaustion classification prevent bursts of commands from overrunning
  a server's SSH session limit.
- **Dead connections are detected and recovered.** SSH keepalives, bounded
  handshakes, bounded control operations, and one controlled redial prevent
  half-open connections from hanging work indefinitely.
- **Broker upgrades cannot silently use old code.** Clients compare the
  resident broker's version and executable identity, shut down stale instances,
  wait for process exit before starting the replacement, and prevent stale
  cleanup from removing the replacement endpoint.
- **Large command payloads bypass operating-system argument limits.** Stdin
  command modes stream scripts over the SSH channel instead of embedding them
  in a remote command line.
- **Completed commands render from the finalized log.** Immediate responses no
  longer lose late output or return an empty body under channel pressure.
- **Finished runs cannot execute twice after a local save failure.** A
  finalize-pending state retains the existing run until its remote log is saved.
- **Detached jobs survive broker and network interruption.** Persisted job
  identity, offsets, and outcome metadata allow a later client call to reattach
  without starting the command again.
- **Full-log finalization has a bounded transfer-specific deadline.** Slow links
  can retrieve the capped log without inheriting the short control-operation
  timeout.
- **Remote cleanup never treats silence as abandonment.** Only completed runs
  with an exit status are eligible for the 24-hour remote sweep.
- **Profile and credential replacement is snapshot-consistent.** The broker
  cannot observe an old target with a newly written credential.
- **Async persistence stores command hashes, not command payloads.** Large stdin
  scripts no longer make every offset update rewrite megabytes of job state.
- **SSH config import follows first-value semantics.** `Host *` and matching
  wildcard defaults now apply to concrete imported aliases.
- **Diagnostics remain non-spawning.** `corv doctor` no longer starts or replaces
  a broker, and TUI credential-removal failures are reported.
- **Concurrent connection edits are serialized.** CLI and TUI profile changes,
  imports, removals, and vault resets share a process-level state lock, so
  concurrent writers cannot silently overwrite one another.
- **Saved secrets retain their exact bytes.** Leading and trailing spaces in
  passwords and private-key passphrases are no longer removed by CLI or CSV
  input handling.
- **Replacing a connection is explicit and credential-safe.** `corv add` reports
  when it replaces an existing name, preserves an existing credential when no
  replacement is entered, and removes superseded vault entries.
- **`corv status` tolerates older resident brokers.** After an upgrade, an
  incompatible broker is reported as unavailable instead of returning an
  `unknown op` failure; status remains non-spawning.
- **Credential cleanup failures are reported.** `corv rm` no longer prints
  success if the saved profile was removed but its vault entry could not be
  deleted.
- **Profile rename no longer loses credentials.** Renaming a connection in the
  TUI now preserves its stored password/passphrase (the "leave empty to keep"
  behavior) and only removes the old secret after the new state is saved.
- **Vault read failures are reported, not masked.** A damaged or unavailable
  vault previously surfaced as an SSH "authentication failed" error. Corv now
  reports the actual credential-read problem so the diagnosis is correct.
- **Key authentication degrades gracefully.** When an explicit identity file
  cannot be loaded (for example, an encrypted key without a passphrase), Corv
  still offers ssh-agent and password authentication instead of aborting.
- **`corv output` exit codes are consistent.** A still-running job exits `75`,
  a completed job exits with its recorded remote exit code, and only tool
  failures exit `1`, identical across plain and `--json` output, and matching
  the JSON `exit_code` field.
- **Agent JSON responses are complete during failures.** Infrastructure errors
  (config load, broker, executable resolution) now return valid JSON with an
  `error_kind` when `--json` is requested, instead of plain text.
- **`corv output` JSON always reports run state.** `running` and `exit_code`
  are always present, so a polling agent can distinguish a live run from a
  failure.
- **`corv uninstall` reports failures honestly.** It now exits non-zero when the
  binary or data directory could not be removed.

### Changed

- **Release publication is gated.** Tag builds publish only after build, vet,
  static analysis, formatting, the Linux race-detector test suite, and a
  reachable-vulnerability scan pass.
- **Upgrade compatibility is regression-tested.** Golden v1.0.1 encrypted
  profile and vault fixtures are opened without modifying their bytes.
- **Crash-safe local state.** Config, vault, job state (`jobs.json`), saved run
  logs, imported private keys, and the broker endpoint file are now written
  atomically (temporary file, flushed to disk, then renamed), so a crash or
  power loss cannot corrupt or lose them.
- **Stable vault key selection.** The vault records which key backend sealed it
  and reads through all available keys, so a change in keychain availability
  between runs no longer locks you out of existing secrets. Existing vaults are
  read as-is and pinned on the next save; no re-encryption or migration step is
  required.
- **Private local plumbing.** Broker IPC uses an owner-restricted Unix socket or
  Windows named pipe, remote detached-job files use a per-user `0700`
  directory, and local state files remain `0600`.
- **Bounded SSH handshakes.** The connection timeout now covers the full SSH
  handshake, not just the TCP connection, so an unresponsive or hostile endpoint
  can no longer hang a connection indefinitely. Applies to direct and
  bastion/jump connections.
- **Self-update is hardened.** Downloads are size-bounded, checksums are matched
  by exact filename, and the running toolchain is pinned to Go 1.26.5.
- **README accuracy.** Corrected claims about raw SSH credential handling and
  OpenSSH connection multiplexing.

### Security

- Added `SECURITY.md` with a private vulnerability-reporting process.
- Upgraded the build toolchain to Go 1.26.5 to pick up standard-library fixes
  (`govulncheck` reports zero reachable vulnerabilities).

## v1.0.1 - 2026-06-27

Initial public release (packaging and install fixes over v1.0).

## v1.0 - 2026-06-27

Initial release of Corv: the SSH client for AI agents and humans.
