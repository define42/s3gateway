# Contributing to s3gateway

Thank you for contributing. Keep each change focused, include tests for changed
behavior, and do not commit production credentials, private keys, or service
endpoints.

## Prerequisites

- Go 1.26.6 or later
- Git
- Docker Engine with the Compose plugin
- Network access for Go modules, lint and security tools, and test container
  images

Docker must be running for the full test suite. Integration tests use
`testcontainers-go` to start LDAP, MinIO, and Ceph containers.

## Set up the repository

```bash
git clone https://github.com/define42/s3gateway.git
cd s3gateway
go mod download
```

Build the gateway without starting its dependencies:

```bash
go build ./cmd/s3gateway
```

To run the local MinIO, LDAP, and gateway stack:

```bash
docker compose up --build
```

The local service URLs and test credentials are documented in the
[README](README.md#local-docker-compose-stack). Stop the stack with
`Ctrl+C`, then remove its containers and network:

```bash
docker compose down
```

The named `minio-data` volume is retained. Add `--volumes` only when you
intentionally want to delete the local MinIO data as well.

## Format and test changes

Format modified Go files before running checks:

```bash
gofmt -w path/to/changed.go path/to/changed_test.go
```

Run the checks used by the main Go workflow:

```bash
make lint
go test ./... -coverprofile=coverage.out -covermode=atomic -coverpkg=./...
```

`make test` is a shorter equivalent when you need package-wide coverage but do
not need a coverage profile:

```bash
make test
```

When changing concurrency, authentication, or request handling, also run the
race detector:

```bash
go test -race ./...
```

Run the security scanner for security-sensitive changes:

```bash
make gosec
```

The `lint` target pins its golangci-lint release so local and CI checks use the
same rules. The `gosec` target downloads its latest release. To run a focused
package or test while developing:

```bash
go test ./internal/server
go test ./internal/server -run '^TestName$'
```

## Benchmarks

The benchmark workflow runs the full gateway integration benchmarks against
containerized services:

```bash
go test -run '^$' \
  -bench '^BenchmarkFullIntegrationGateway(PutObject|GetObject)$' \
  -benchmem -count=3 -benchtime=3x ./...
```

Docker must be available, and the run can take several minutes.

## Code and documentation style

- Follow standard Go naming and formatting conventions.
- Prefer focused functions and table-driven tests for branching behavior.
- Document new or changed environment variables in the README configuration
  table.
- Keep S3 compatibility and behavior descriptions synchronized with the
  implemented routes.
- Name templates and static assets by feature.

## Pull requests

Before opening a pull request:

1. Rebase or merge the current `main` branch and resolve conflicts.
2. Run the relevant lint, test, race, and security checks above.
3. Review the diff for credentials, private keys, generated coverage files, and
   unrelated changes.

The pull-request description should include:

- a concise summary and motivation
- a linked issue, when applicable
- the commands run locally and their results
- configuration or environment-variable changes
- screenshots for admin console or template changes

Use a short, verb-led commit subject such as `Added ...`, `Updated ...`,
`Fixed ...`, or `Removed ...`, and keep commits single-purpose.
