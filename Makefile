.PHONY: all dev build web-build agents test clean install-deps sqlc help

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

LD_FLAGS = -ldflags="-X runic/internal/common/version.Version=$(VERSION) -X runic/internal/common/version.Commit=$(COMMIT) -X runic/internal/common/version.BuiltAt=$(BUILT_AT)"

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
	CGO_ENABLED=1 $(GOBUILD) $(LD_FLAGS) -o $(BINARY_SERVER) .

# Build agent binaries for all platforms
agents: agents-linux-amd64 agents-linux-arm64 agents-linux-arm agents-linux-armv6

agents-linux-amd64:
	@mkdir -p dist
	@echo "$(GREEN)Building agent for linux/amd64...$(NC)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_AGENT)-linux-amd64 $(AGENT_DIR)

agents-linux-arm64:
	@mkdir -p dist
	@echo "$(GREEN)Building agent for linux/arm64...$(NC)"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BINARY_AGENT)-linux-arm64 $(AGENT_DIR)

agents-linux-arm:
	@mkdir -p dist
	@echo "$(GREEN)Building agent for linux/arm...$(NC)"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm $(GOBUILD) -o $(BINARY_AGENT)-linux-arm $(AGENT_DIR)

agents-linux-armv6:
	@mkdir -p dist
	@echo "$(GREEN)Building agent for linux/armv6...$(NC)"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 $(GOBUILD) -o $(BINARY_AGENT)-linux-armv6 $(AGENT_DIR)

# Build web frontend
web-build:
	@echo "$(GREEN)Building web frontend...$(NC)"
	@cd web && npm install --silent && npm run build

# Run tests
test:
	@echo "$(GREEN)Running tests...$(NC)"
	$(GOTEST) -v ./...

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
	golangci-lint run ./... || true

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
	@echo " make clean - Clean build artifacts"
	@echo " make install-deps - Install all dependencies"
	@echo " make fmt - Format Go code"
	@echo " make lint - Run linter"
	@echo ""
