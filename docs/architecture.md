# Corv Architecture

Corv is a local SSH client. It stores connection profiles and credentials on
the client, keeps authenticated SSH connections warm in a local broker, and
runs commands through independent SSH channels. Remote execution requires a
POSIX shell, but no Corv process or package is installed remotely.

## Package boundaries

Dependencies point inward from `internal/cli` and `internal/tui` to focused
packages:

- `profile`, `vault`, and `paths` own durable local configuration.
- `statelock` serializes cross-process profile and credential mutations.
- `atomicfile` provides crash-safe replacement for durable files.
- `sshconn` owns SSH transport, authentication, host-key verification,
  bastions, command channels, and interactive shells.
- `broker` owns warm connections, detached-run coordination, and local IPC.
- `output` cleans and bounds remote output without interpreting commands.
- `audit` records local command history.

The broker package is split by responsibility: `server.go` handles IPC and
connection ownership, `jobs.go` implements the detached-run lifecycle,
`run_protocol.go` defines the remote shell protocol, `run_output.go` retrieves
and finalizes run output, `job_store.go` defines the durable record, and
`job_registry.go` synchronizes registry updates.

## Detached-run state

The normal state progression is:

```text
pending -> starting -> running -> finalize_pending -> done
                  \-> failed
```

`finalize_pending` means the remote command has a terminal result but its log
has not been saved durably on the client. Corv must retry finalization and must
not execute the command again. `expired` and `unknown` mean the remote
artifacts no longer prove an outcome. They have no reliable exit code,
duration, or completion time.

Run identity is persisted before remote start. A caller-supplied run key is
bound to the profile, command hash, and connection fingerprint. The binding
prevents a retry from silently applying the same key to different work or a
different endpoint.

Remote files live in the per-user temporary run directory with owner-only
permissions. Completed output is copied to the local runs directory before
remote cleanup. Inline responses are bounded independently from the retained
local log.

## Broker synchronization

Mutex ownership is deliberately narrow:

- `server.mu` protects the profile-entry map.
- `entry.mu` protects one profile's connection snapshot, dial state, and
  in-memory job map.
- `job.startMu` permits one remote start attempt.
- `job.pollMu` permits one poll or finalization for a run.
- `job.mu` protects the run's mutable state.
- `server.jobsMu` protects the persisted registry snapshot and its writes.

Global locks must not be held across SSH or IPC operations. Per-entry locking
may serialize connection replacement for one profile, but must not block work
on another profile. Code that needs both an entry and a job takes the entry
lock only long enough to find or replace the job, then uses the job locks.
Registry persistence snapshots job state before taking `jobsMu`; it does not
hold `jobsMu` while waiting on SSH.

The race-detector CI job is the dynamic check for these invariants. Changes to
lock ownership or acquisition order require a focused concurrency test.

## Compatibility

Profile, vault, endpoint, and job fields are additive. Missing fields retain
their legacy meaning. Existing encrypted state must remain readable without a
migration step, and reads must not rewrite state unless an explicit legacy
migration already defines that behavior.
