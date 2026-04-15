.PHONY: all dev build web-build agents test test-go test-web clean install-deps sqlc help lint lint-go lint-web verify

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
BINARY_SERVER=dist/runic-server
BINARY_AGENT=dist/runic-agent
SERVER_DIR=./cmd/runic-server
AGENT_DIR=./cmd/runic-agent

# Colors for output
GREEN=\033[0;32m
NC=\033[0m # No Color

# Version information (injected at build time)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILT_AT ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Agent version from .agent-version file
AGENT_VERSION ?= $(shell cat .agent-version 2>/dev/null || echo "dev")

LD_FLAGS = -ldflags="-X runic/internal/common/version.Version=$(VERSION) -X runic/internal/common/version.Commit=$(COMMIT) -X runic/internal/common/version.BuiltAt=$(BUILT_AT)"
AGENT_LD_FLAGS = -ldflags="-X runic/internal/agent/core.Version=$(AGENT_VERSION)"

all: web-build build

# Development mode with live reload
dev:
	@echo "$(GREEN)Starting development server...$(NC)"
	@go run . &
	@cd web && npm run dev

# Build server with CGO for SQLite
build: $(BINARY_SERVER)

$(BINARY_SERVER):
	@mkdir -p dist
	@echo "$(GREEN)Building runic-server (CGO enabled)...$(NC)"
	CGO_ENABLED=1 $(GOBUILD) $(LD_FLAGS) -o $(BINARY_SERVER) $(SERVER_DIR)

# Build agent binaries for all platforms
agents: agents-linux-amd64 agents-linux-arm64 agents-linux-arm agents-linux-armv6

agents-linux-amd64:
	@mkdir -p dist
	@echo "$(GREEN)Building agent for linux/amd64...$(NC)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(AGENT_LD_FLAGS) -o $(BINARY_AGENT)-linux-amd64 $(AGENT_DIR)

agents-linux-arm64:
	@mkdir -p dist
	@echo "$(GREEN)Building agent for linux/arm64...$(NC)"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) $(AGENT_LD_FLAGS) -o $(BINARY_AGENT)-linux-arm64 $(AGENT_DIR)

agents-linux-arm:
	@mkdir -p dist
	@echo "$(GREEN)Building agent for linux/arm...$(NC)"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm $(GOBUILD) $(AGENT_LD_FLAGS) -o $(BINARY_AGENT)-linux-arm $(AGENT_DIR)

agents-linux-armv6:
	@mkdir -p dist
	@echo "$(GREEN)Building agent for linux/armv6...$(NC)"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 $(GOBUILD) $(AGENT_LD_FLAGS) -o $(BINARY_AGENT)-linux-armv6 $(AGENT_DIR)

# Build web frontend
web-build:
	@echo "$(GREEN)Building web frontend...$(NC)"
	@cd web && npm install --silent && npm run build

# Existing test target update
test: test-go test-web

# Go backend testing with race detection and coverage
test-go:
	@echo "$(GREEN)Running Go tests...$(NC)"
	$(GOTEST) -v -race -cover ./...

# React frontend testing
test-web:
	@echo "$(GREEN)Running React tests...$(NC)"
	cd web && npm ci && npm run test -- --run

# Clean build artifacts
clean:
	@echo "$(GREEN)Cleaning...$(NC)"
	rm -rf dist/
	rm -f runic.db rununic.db-shm runic.db-wal

# Install Go dependencies
install-deps:
	@echo "$(GREEN)Installing Go dependencies...$(NC)"
	$(GOMOD) download
	@echo "$(GREEN)Installing frontend dependencies...$(NC)"
	cd web && npm install

# Generate SQL code with sqlc (if used)
sqlc:
	@echo "$(GREEN)Generating SQL code...$(NC)"
	@which sqlc > /dev/null || go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	sqlc generate

# Format code
fmt:
	$(GOCMD) fmt ./...

# Run linter
lint:
	golangci-lint run ./...

# Updated Run linter target
lint: lint-go lint-web

# Go-specific linting
lint-go:
	@echo "$(GREEN)Linting Go code...$(NC)"
	golangci-lint run ./...

# React-specific linting
lint-web:
	@echo "$(GREEN)Linting React code...$(NC)"
	cd web && npm run lint

# Unified verification target
verify: clean fmt lint test build
	@echo "$(GREEN)All systems go. Runic is ready for commit.$(NC)"

# Show help
help:
	@echo "Runic Firewall Management System - Build Targets"
	@echo ""
	@echo " make all - Build everything (web + server)"
	@echo " make dev - Start development server with live reload"
	@echo " make build - Build server binary (CGO enabled)"
	@echo " make web-build - Build web frontend only"
	@echo " make agents - Build agent binaries for all platforms"
	@echo " make test - Run tests"
	@echo " make test-go - Run Go tests"
	@echo " make test-web - Run React tests"
	@echo " make clean - Clean build artifacts"
	@echo " make install-deps - Install all dependencies"
	@echo " make fmt - Format Go code"
	@echo " make lint - Run all linters (Go and React)"
	@echo " make lint-go - Run Go linter only"
	@echo " make lint-web - Run React linter only"
	@echo " make verify - Run fmt, lint, test, and build for Go and React"
	@echo ""
