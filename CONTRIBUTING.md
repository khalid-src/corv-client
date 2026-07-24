# Contributing to Corv

Thanks for your interest in Corv. This document covers how to build, test, and
propose changes.

## Scope

Corv is an SSH **client** for AI agents and humans. It connects by name, reuses
warm authenticated connections, keeps secrets in a local encrypted vault, and
returns structured output. It is deliberately not a platform: no policy engine,
no denylists, no cloud service, no server-side component. Changes that keep the
client small, correct, and portable are welcome; feature requests that turn it
into a platform are generally out of scope.

## Development

Requires Go 1.25 or newer. With Go's default toolchain selection enabled, the
version pinned in `go.mod` is selected automatically.

```sh
go build ./...
go vet ./...
go test ./...
```

The Makefile provides convenience targets, including `make build-all`, on
systems where `make` is available.

## Before opening a pull request

Every change must pass the same gate that CI enforces:

```sh
go build ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
gofmt -l .                 # must print nothing
go test -race -count=1 ./...
```

Guidelines:

- Add tests for the behavior you change; durable on-disk formats also need to
  keep reading existing data (see the upgrade-compatibility fixtures under
  `internal/vault/testdata`).
- Keep comments and commit messages engineering-neutral.
- Never commit secrets, keys, vaults, logs, or built binaries.

## Reporting security issues

Do not open a public issue for a suspected vulnerability. Follow
[SECURITY.md](SECURITY.md).
