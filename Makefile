# Development entry points. `make` with no target lists them.
#
# Same shape as organization-control and identity-control, including the cmd.exe traps those
# two paid for: `exit 1` rather than `exit /b 1` (which does not set cmd /c's exit code),
# findstr rather than `for /f` for the gofmt gate (which exits 1 over an empty file), and
# psql options before the connection string (the Windows psql stops parsing options at the
# first positional argument and then silently reads an empty stdin).

SHELL := cmd.exe
.SHELLFLAGS := /c

-include .env
export

ADDR ?= 127.0.0.1:8096
AUTHORITY ?= 127.0.0.1:8099

.DEFAULT_GOAL := help
.PHONY: help env migrate run deliver build fmt vet tidy test test-unit test-integration gates clean

help:
	@echo Targets:
	@echo   make env               copy .env.example to .env (does not overwrite)
	@echo   make migrate           platform schema, then projection.membership
	@echo   make run               the consumer on $(ADDR)
	@echo   make deliver F=e.json  post one CloudEvents envelope to the intake
	@echo   make gates             fmt vet build tidy test
	@echo   make test-integration  requires .env and a running PostgreSQL
	@echo.
	@echo   Enforcement, by hand -- the four classes differ only in what they do
	@echo   when the projection cannot answer:
	@echo     GET  /v1/directory/{id}        LOW_RISK             fail-open, bounded
	@echo     GET  /v1/payroll/{id}          HIGH_CONFIDENTIALITY fail-closed
	@echo     POST /v1/administration/{id}   PRIVILEGED           asks the authority
	@echo     POST /v1/deletion/{id}         IRREVERSIBLE         asks the authority

env:
	@if exist .env (echo .env already exists -- leaving it alone) else (copy .env.example .env >nul && echo Created .env from .env.example)

migrate:
	@if not exist .env (echo No .env yet. Run: make env && exit 1)
	go run ./cmd/foundation-reference-migrate

run:
	@if not exist .env (echo No .env yet. Run: make env && exit 1)
	go run ./cmd/foundation-reference

# The body is a file. Quoting a CloudEvents envelope on a cmd line means escaping every
# double quote, and one missed backslash produces a 400 that reads as the consumer rejecting
# a valid delivery.
deliver:
	@if "$(F)"=="" (echo Usage: make deliver F=envelope.json && exit 1)
	@if not exist $(F) (echo Not found: $(F) && exit 1)
	@curl.exe -s -i -X POST -H "Content-Type: application/json" --data-binary "@$(F)" "http://$(ADDR)/v1/deliveries"

build:
	go build ./...

fmt:
	@gofmt -l . > .fmt.tmp
	@findstr /r /c:"." .fmt.tmp >nul && (echo Not gofmt-clean: && type .fmt.tmp && del .fmt.tmp && exit 1) || (del .fmt.tmp && echo gofmt clean)

vet:
	go vet ./...

tidy:
	go mod tidy
	@git diff --exit-code go.mod go.sum || (echo go.mod or go.sum changed -- commit the result && exit 1)

test:
	go test ./... -race -count=1

# No database needed: the enforcement policy is unit-tested through an interface, precisely
# so the branch where the projection read fails is reachable without breaking a database.
test-unit:
	go test ./internal/httpapi/... -race -count=1

# REQUIRE_INTEGRATION turns a skip into a failure. Without it an unreachable database leaves
# the projection assertions unrun and the suite green.
test-integration:
	@if not exist .env (echo No .env yet. Run: make env && exit 1)
	set REQUIRE_INTEGRATION=1&& go test ./internal/... -race -count=1

gates: fmt vet build tidy test
	@echo All gates passed.

clean:
	go clean -cache -testcache
