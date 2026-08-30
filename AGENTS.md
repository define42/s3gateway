# Repository Guidelines

## Project Structure & Module Organization

This is a Go application with its entry point in `cmd/s3gateway/`. Application composition and gateway code live under `internal/` (for example `internal/app`, `internal/server`, `internal/config`, `internal/s3credentials`, and `internal/certreader`).
HTML admin templates live in `internal/adminpage/webtemplate/`.
Test fixtures for local LDAP live in `testldap/`.
Encrypted example clients are in `example_s3_client/python/` and
`example_s3_client/golang/`. The X25519 key generator is in the Python folder.
Tests are colocated with their packages under `internal/`. Docker-backed integration tests live in `internal/app/`, and gateway benchmarks live in `internal/server/`.

## Build, Test, and Development Commands

- `go run ./cmd/s3gateway`: run the gateway locally.
- `make lint`: run `golangci-lint`.
- `make test`: run all tests with package-wide coverage (`go test ./... -coverpkg=./...`).
- `go test -race ./...`: run race detection.
- `make gosec`: run `gosec` static security checks.
- `docker compose up --build` (or `make run`): start local MinIO + LDAP + gateway stack.

CI (`.github/workflows/go.yml`) runs lint, coverage tests, and Codecov upload; keep local checks aligned before opening a PR.

## Coding Style & Naming Conventions

Use standard Go formatting (`gofmt`) and idiomatic Go naming:

- exported identifiers: `PascalCase`
- unexported identifiers: `camelCase`
- test files: `*_test.go`

Keep functions focused and prefer table-driven tests for branching logic. Keep templates and static assets named by feature (for example `internal/adminpage/webtemplate/admin-dashboard.html`).

## Testing Guidelines

Use Go’s `testing` package for unit and integration coverage. Integration tests rely on Docker via `testcontainers-go`; ensure Docker is available before running them.
Benchmark names follow Go conventions (`Benchmark...`) and are run in CI via `.github/workflows/benchmark.yml`.

Before submitting changes, run at minimum:

- `make lint`
- `go test ./...`

If concurrency, auth, or request handling changed, also run `go test -race ./...`.

## Commit & Pull Request Guidelines

Recent history uses short, verb-led commit subjects (for example: `Added ...`, `Updated ...`, `Fixed ...`, `Removed ...`). Keep commits single-purpose and messages specific.

PRs should include:

- concise change summary and motivation
- linked issue (if applicable)
- commands run locally (lint/test/race)
- screenshots for admin UI/template changes
- notes on config/env var changes

## Security & Configuration Tips

Do not commit real credentials, private keys, or production LDAP/S3 endpoints. Use environment variables for secrets and keep test-only values in local/dev configs.
