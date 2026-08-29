GOLANGCI_LINT_VERSION := v2.13.2

.PHONY: all lint gosec test run

all:
	docker compose build

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest ./...

test:
	go test ./... -coverpkg=./...

run:
	docker compose stop
	docker compose build
	docker compose up
