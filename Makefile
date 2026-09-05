GOLANGCI_LINT_VERSION := v2.13.2
GOVULNCHECK_VERSION := v1.7.0

.PHONY: all coverage integration lint gosec govulncheck test race tidy-check run

all:
	docker compose build

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest ./...

govulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

test:
	@cover_packages="$$(go list ./cmd/s3gateway ./internal/... | grep -v '/internal/testutil$$' | paste -sd, -)"; \
	go test -shuffle=on -count=1 ./... -coverpkg="$$cover_packages"

coverage:
	@cover_packages="$$(go list ./cmd/s3gateway ./internal/... | grep -v '/internal/testutil$$' | paste -sd, -)"; \
	go test -shuffle=on -count=1 ./... -coverprofile=coverage-unit.out -covermode=atomic -coverpkg="$$cover_packages"

integration:
	go test -race -tags=integration -shuffle=on -count=1 ./internal/app ./internal/server ./internal/ldap

race:
	go test -race -shuffle=on -count=1 ./...

tidy-check:
	go mod tidy -diff

run:
	docker compose stop
	docker compose build
	docker compose up
