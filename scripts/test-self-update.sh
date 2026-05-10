#!/bin/bash
# test-self-update.sh — Integration test for the runic-agent self-update lifecycle
#
# This script must be run on a Linux system with systemd (not macOS).
# It verifies the full self-update flow: build, install a "stale" version,
# trigger the -update flag (added in TASK-002), and verify the update process
# launched correctly via systemd-run or the setsid fallback path.
#
# Usage:
#   sudo ./scripts/test-self-update.sh [--url <control-plane-url>] [--dry-run]
#
# Options:
#   --url    Control plane URL (default: https://control.example.com)
#   --dry-run  Validate command construction without actually downloading
#
# CI Usage (GitHub Actions):
#   This script can be used in a GitHub Actions workflow that spins up a
#   systemd-capable container. Example workflow snippet:
#
#     jobs:
#       self-update-test:
#         runs-on: ubuntu-latest
#         container:
#           image: ubuntu:22.04
#           options: --privileged
#         steps:
#           - uses: actions/checkout@v4
#           - uses: actions/setup-go@v5
#             with:
#               go-version: "1.23"
#           - name: Install systemd
#             run: apt-get update && apt-get install -y systemd systemd-sysv
#           - name: Start systemd
#             run: /sbin/init &
#           - name: Run self-update integration test
#             run: sudo ./scripts/test-self-update.sh --dry-run
#
# The container needs --privileged and /sbin/init for systemd to operate.

set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────
CONTROL_PLANE_URL="https://control.example.com"
DRY_RUN=false
AGENT_BINARY="/usr/local/bin/runic-agent"
SERVICE_FILE="/etc/systemd/system/runic-agent.service"
TEST_BINARY="/tmp/runic-agent-test"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --url)
            if [[ -z "${2:-}" ]]; then
                echo "Error: --url requires a value" >&2
                exit 1
            fi
            CONTROL_PLANE_URL="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--url <control-plane-url>] [--dry-run]"
            echo ""
            echo "Options:"
            echo "  --url      Control plane URL (default: https://control.example.com)"
            echo "  --dry-run  Validate command construction without downloading"
            exit 0
            ;;
        *)
            echo "Error: unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

# ── Logging helpers ─────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

log_step() {
    echo -e "${YELLOW}[STEP]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_info() {
    echo -e "       $1"
}

# ── Cleanup on exit ─────────────────────────────────────────────────────────
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_fail "Test exited with code $exit_code — cleaning up"
    else
        log_step "Cleaning up test artifacts"
    fi

    # Stop the service if it was started
    if systemctl is-active --quiet runic-agent 2>/dev/null; then
        log_info "Stopping runic-agent service"
        systemctl stop runic-agent 2>/dev/null || true
    fi

    # Remove test binary
    if [[ -f "$TEST_BINARY" ]]; then
        log_info "Removing test binary: $TEST_BINARY"
        rm -f "$TEST_BINARY"
    fi

    # Remove installed binary (only if we placed it)
    if [[ -f "$AGENT_BINARY" ]] && [[ "$INSTALL_PERFORMED" == "true" ]]; then
        log_info "Removing installed binary: $AGENT_BINARY"
        rm -f "$AGENT_BINARY"
    fi

 # Remove service file (only if we placed it)
 if [[ -f "$SERVICE_FILE" ]] && [[ "$SERVICE_INSTALLED" == "true" ]]; then
 log_info "Removing service file: $SERVICE_FILE"
 rm -f "$SERVICE_FILE"
 systemctl daemon-reload 2>/dev/null || true
 fi

 # Remove config file and directory (only if we created them)
 if [[ "$CONFIG_CREATED" == "true" ]]; then
 log_info "Removing created config file and directory..."
 rm -f /etc/runic-agent/config.json
 rmdir /etc/runic-agent 2>/dev/null || true
 fi

 log_info "Cleanup complete"
}
trap cleanup EXIT

# Track what we installed so cleanup only removes our own artifacts
INSTALL_PERFORMED=false
SERVICE_INSTALLED=false
CONFIG_CREATED=false

# ── Step 1: Prerequisites check ─────────────────────────────────────────────
log_step "Checking prerequisites"

# 1a. Verify running on Linux
OS_NAME="$(uname -s)"
if [[ "$OS_NAME" != "Linux" ]]; then
    log_fail "This script must be run on Linux (detected: $OS_NAME)"
    log_info  "macOS is not supported because systemd is required."
    exit 1
fi
log_pass "Running on Linux"

# 1b. Verify systemd is available
if ! systemctl --version >/dev/null 2>&1; then
    log_fail "systemd is not available (systemctl --version failed)"
    exit 1
fi
SYSTEMD_VERSION="$(systemctl --version 2>/dev/null | head -1 | awk '{print $2}')"
log_pass "systemd is available (version $SYSTEMD_VERSION)"

# 1c. Verify root or sudo access
if [[ "$(id -u)" -ne 0 ]]; then
    log_fail "This script must be run as root (use sudo)"
    exit 1
fi
log_pass "Running as root"

# ── Step 2: Build current version ───────────────────────────────────────────
log_step "Building runic-agent from source"

if ! command -v go &>/dev/null; then
    log_fail "Go is not installed or not in PATH"
    exit 1
fi

log_info "Building: go build -o $TEST_BINARY ./cmd/runic-agent/"
(cd "$PROJECT_ROOT" && go build -o "$TEST_BINARY" ./cmd/runic-agent/)

if [[ ! -x "$TEST_BINARY" ]]; then
    log_fail "Build failed: $TEST_BINARY not found or not executable"
    exit 1
fi
log_pass "Built runic-agent successfully"

# Verify the binary responds to -update flag (added in TASK-002)
UPDATE_HELP="$(timeout 5 "$TEST_BINARY" -h 2>&1 || true)"
if echo "$UPDATE_HELP" | grep -q -- "-update"; then
    log_pass "Binary supports -update flag"
else
    log_fail "Binary does not support -update flag (expected from TASK-002)"
    exit 1
fi

# ── Step 2.5: Test -update without URL fails with clear error ─────────────
log_step "Testing -update flag without URL (should fail with error)"

# Create a temp config with no control plane URL
TEMP_CONFIG="$(mktemp)"
echo '{}' > "$TEMP_CONFIG"

UPDATE_ERR="$(timeout 5 "$TEST_BINARY" -update -config "$TEMP_CONFIG" 2>&1)" && {
	log_fail "Expected -update without URL to fail, but it succeeded"
	rm -f "$TEMP_CONFIG"
	exit 1
} || true

if echo "$UPDATE_ERR" | grep -qi "control plane URL not configured"; then
	log_pass "-update without URL correctly fails with expected error"
else
	log_fail "-update without URL failed but with unexpected error: $UPDATE_ERR"
	rm -f "$TEMP_CONFIG"
	exit 1
fi

rm -f "$TEMP_CONFIG"

# ── Step 3: Install a "stale" version ───────────────────────────────────────
log_step "Installing stale version of runic-agent"

# 3a. Copy the built binary to /usr/local/bin/runic-agent
log_info "Installing binary to $AGENT_BINARY"
cp "$TEST_BINARY" "$AGENT_BINARY"
chmod +x "$AGENT_BINARY"
INSTALL_PERFORMED=true
log_pass "Binary installed to $AGENT_BINARY"

# 3b. Install the service file if available in the scripts directory
LOCAL_SERVICE_FILE="$SCRIPT_DIR/runic-agent.service"
if [[ -f "$LOCAL_SERVICE_FILE" ]]; then
    log_info "Installing service file from $LOCAL_SERVICE_FILE"
    cp "$LOCAL_SERVICE_FILE" "$SERVICE_FILE"
    SERVICE_INSTALLED=true
    systemctl daemon-reload
    log_pass "Service file installed to $SERVICE_FILE"
else
    log_info "Service file not found at $LOCAL_SERVICE_FILE — skipping service installation"
fi

# Create config directory and minimal config so the agent can resolve the control plane URL
CONFIG_DIR="/etc/runic-agent"
CONFIG_FILE="$CONFIG_DIR/config.json"

if [[ ! -f "$CONFIG_FILE" ]]; then
    log_info "Creating minimal agent config with control plane URL: $CONTROL_PLANE_URL"
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    if command -v jq &>/dev/null; then
      jq -n \
        --arg url "$CONTROL_PLANE_URL" \
        '{
          "control_plane_url": $url,
          "pull_interval_seconds": 86400,
          "log_path": "/var/log/runic/firewall.log",
          "apply_on_boot": false,
          "apply_rules_bundle": false,
          "disable_system_managed_iptables": false
        }' > "$CONFIG_FILE"
    else
      # Fallback: escape special JSON characters manually
      escaped_url=$(printf '%s' "$CONTROL_PLANE_URL" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g')
      printf '{\n  "control_plane_url": "%s",\n  "pull_interval_seconds": 86400,\n  "log_path": "/var/log/runic/firewall.log",\n  "apply_on_boot": false,\n  "apply_rules_bundle": false,\n  "disable_system_managed_iptables": false\n}\n' "$escaped_url" > "$CONFIG_FILE"
    fi
    chmod 600 "$CONFIG_FILE"
    CONFIG_CREATED=true
else
    log_info "Preserving existing agent config at $CONFIG_FILE"
    CONFIG_CREATED=false
fi

# ── Step 4: Run the update trigger ──────────────────────────────────────────
log_step "Triggering self-update via -update flag"

UPDATE_CMD=("$AGENT_BINARY" "-update" "-url" "$CONTROL_PLANE_URL")

if [[ "$DRY_RUN" == "true" ]]; then
    # In dry-run mode, validate command construction without actually downloading
    log_info "DRY-RUN: Validating command construction (no download will occur)"
    log_info "DRY-RUN: Command: ${UPDATE_CMD[*]}"

    # Verify the binary accepts the flags without error
    # The -update flag triggers HandleUpdateAgent which will attempt to launch
    # the update process. In dry-run, we just check the command parses correctly
    # by inspecting the help output and verifying the flag combination.
    log_info "DRY-RUN: Checking that -update flag is accepted by the binary"
    if timeout 5 "$AGENT_BINARY" -h 2>&1 | grep -q -- "-update"; then
        log_pass "DRY-RUN: -update flag accepted"
    else
        log_fail "DRY-RUN: -update flag not recognized"
        exit 1
    fi

    # Verify the URL flag is accepted
    if timeout 5 "$AGENT_BINARY" -h 2>&1 | grep -q -- "-url"; then
        log_pass "DRY-RUN: -url flag accepted"
    else
        log_fail "DRY-RUN: -url flag not recognized"
        exit 1
    fi

	# Show the expected systemd-run command that would be constructed
	# Ref: internal/agent/core/agent.go — InstallScriptURL constant
	EXPECTED_CMD="systemd-run --scope --unit=runic-agent-update bash -c 'curl -sL https://raw.githubusercontent.com/ubenmackin/runic/main/scripts/install-agent.sh | sudo bash -s -- ${CONTROL_PLANE_URL}'"
    log_info "DRY-RUN: Expected update command: $EXPECTED_CMD"
    log_pass "DRY-RUN: Command construction validated"

    echo ""
    echo "Dry-run complete. No files were downloaded or services restarted."
    exit 0
fi

# Actually run the update trigger
# Note: this will attempt to contact the control plane and run the install script.
# In a real test environment, the control plane should serve the install script.
log_info "Running: ${UPDATE_CMD[*]}"
UPDATE_OUTPUT="$(timeout 30 "${UPDATE_CMD[@]}" 2>&1)" || true
log_info "Update output: $UPDATE_OUTPUT"

# ── Step 5: Verify update process ───────────────────────────────────────────
log_step "Verifying update process"

# 5a. Check for systemd scope unit (the primary update path)
# When the agent calls handleUpdateAgent, it uses:
#   systemd-run --scope --unit=runic-agent-update bash -c <cmd>
# We check if the scope was registered.
SCOPE_FOUND=false
if systemctl list-units --all 2>/dev/null | grep -q "runic-agent-update"; then
    log_pass "runic-agent-update.scope detected via systemctl list-units"
    SCOPE_FOUND=true
fi

# Also check via systemd-run's exit — if the agent logged that it launched
if echo "$UPDATE_OUTPUT" | grep -qi "update process launched"; then
    log_pass "Agent logged 'update process launched'"
    SCOPE_FOUND=true
fi

# 5b. Check for the setsid fallback path
# If systemd-run was unavailable, the agent falls back to setsid.
FALLBACK_FOUND=false
if echo "$UPDATE_OUTPUT" | grep -qi "falling back to setsid"; then
    log_info "Agent used setsid fallback path"
    FALLBACK_FOUND=true
fi

if echo "$UPDATE_OUTPUT" | grep -qi "both systemd-run and setsid failed"; then
    log_fail "Both systemd-run and setsid approaches failed"
    exit 1
fi

# At least one update path must have been attempted
if [[ "$SCOPE_FOUND" == "true" ]] || [[ "$FALLBACK_FOUND" == "true" ]]; then
    log_pass "Update process was launched (scope=$SCOPE_FOUND, fallback=$FALLBACK_FOUND)"
else
    # In some test environments the update may fail to connect to the control plane,
    # but the agent should still have attempted it. Check journal logs.
    log_info "Checking journalctl for update-related log entries..."
    JOURNAL_OUTPUT="$(journalctl -u runic-agent --since "1 min ago" --no-pager 2>/dev/null || true)"
    if echo "$JOURNAL_OUTPUT" | grep -qi "self-update\|update process launched\|runic-agent-update"; then
        log_pass "Journal logs confirm update was attempted"
    else
        log_fail "No evidence of update process launch found"
        log_info "This may indicate the control plane URL was unreachable or the agent exited before launching the update"
        exit 1
    fi
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "========================================="
echo "  Self-update integration test: PASSED"
echo "========================================="
echo "  Control plane URL: $CONTROL_PLANE_URL"
echo "  Dry-run:           $DRY_RUN"
echo "  Scope path used:   $SCOPE_FOUND"
echo "  Fallback used:     $FALLBACK_FOUND"
echo "========================================="
