#!/bin/bash
#
# Runic Firewall Management System - Installation Script
# =========================================================
#
# This script installs the Runic Firewall Control Plane on your system.
# It supports Ubuntu/Debian and openSUSE.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/runic/runic/main/install.sh | sudo bash
#   curl -sL https://raw.githubusercontent.com/runic/runic/main/install.sh | sudo bash -s -- --skip-build
#
# Options:
#   --skip-build       Skip building, assume binaries already exist
#   --non-interactive Run without prompts (use defaults)
#   --control-plane   Specify control plane URL
#   --jwt-secret      Specify JWT secret
#   --hmac-key        Specify HMAC key
#
# =========================================================

set -o pipefail

# ============================================================================
# Configuration and Defaults
# ============================================================================

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Installation paths
INSTALL_DIR="/opt/runic"
DATA_DIR="/opt/runic/data"
SOURCE_DIR="/opt/runic/src"
LOG_FILE="/var/log/runic-install.log"
BINARY_NAME="runic-server"
SERVICE_NAME="runic-server"

# Defaults
DEFAULT_CONTROL_PLANE="localhost:8080"
REPO_URL="https://github.com/ubenmackin/runic.git"
REPO_BRANCH="main"

# Flags
SKIP_BUILD=false
NON_INTERACTIVE=false
PROVIDED_CONTROL_PLANE=""
PROVIDED_JWT_SECRET=""
PROVIDED_HMAC_KEY=""

# Temporary directories for cleanup
TEMP_DIRS=()

# ============================================================================
# Utility Functions
# ============================================================================

log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Log to file
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"

    # Output to console with colors
    case "$level" in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message" >&2
            ;;
        *)
            echo "[$level] $message"
            ;;
    esac
}

# Safe removal function with path validation
# Usage: safe_rm <path> [expected_pattern]
# Example: safe_rm "$SOURCE_DIR" "/opt/runic/*"
safe_rm() {
    local path="$1"
    local pattern="${2:-/opt/runic/*}"  # Default pattern

    # Validate path is not empty
    if [[ -z "$path" ]]; then
        log ERROR "safe_rm: path is empty, refusing to remove"
        return 1
    fi

    # Validate path exists
    if [[ ! -e "$path" ]]; then
        log INFO "safe_rm: path does not exist, nothing to remove: $path"
        return 0
    fi

    # Validate path matches expected pattern
    # Using case for glob-style matching
    case "$path" in
        $pattern)
            log INFO "Removing: $path"
            rm -rf "$path"
            return $?
            ;;
        *)
            log ERROR "safe_rm: path does not match expected pattern '$pattern': $path"
            return 1
            ;;
    esac
}

# Cleanup function for temporary directories
cleanup() {
    for dir in "${TEMP_DIRS[@]}"; do
        safe_rm "$dir"
    done
}
trap cleanup EXIT

log_section() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

prompt_yes_no() {
    local prompt="$1"
    local default="${2:-no}"
    local response
    
    if [ "$NON_INTERACTIVE" = true ]; then
        if [ "$default" = "yes" ]; then
            echo "yes"
            return 0
        else
            echo "no"
            return 1
        fi
    fi
    
    while true; do
        if [ "$default" = "yes" ]; then
            read -p "$prompt [Y/n]: " response
        else
            read -p "$prompt [y/N]: " response
        fi
        
        case "$response" in
            [yY][eE][sS]|[yY])
                echo "yes"
                return 0
                ;;
            [nN][oO]|[nN]|"")
                if [ "$default" = "yes" ]; then
                    return 0
                fi
                echo "no"
                return 1
                ;;
            *)
                echo "Please answer yes or no."
                ;;
        esac
    done
}

prompt_with_default() {
    local prompt="$1"
    local default="$2"
    local response
    
    if [ "$NON_INTERACTIVE" = true ]; then
        echo "$default"
        return 0
    fi
    
    read -p "$prompt [$default]: " response
    if [ -z "$response" ]; then
        echo "$default"
    else
        echo "$response"
    fi
}

generate_secret() {
    openssl rand -hex 32
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

# ============================================================================
# Pre-installation Checks
# ============================================================================

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log ERROR "This script must be run as root (use sudo)"
        log INFO "Usage: sudo $0"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS="$ID"
        OS_VERSION="$VERSION_ID"
    elif [ -f /etc/SuSE-release ]; then
        OS="sles"
        OS_VERSION=$(cat /etc/SuSE-release | grep "VERSION" | awk '{print $3}')
    else
        OS="unknown"
        OS_VERSION="unknown"
    fi
    
    # Normalize
    case "$OS" in
        ubuntu|debian|linuxmint|pop)
            OS_FAMILY="debian"
            ;;
        opensuse|sles|suse)
            OS_FAMILY="suse"
            ;;
        *)
            log WARN "Unknown OS: $OS $OS_VERSION, defaulting to Debian-style"
            OS_FAMILY="debian"
            ;;
    esac
    
    log INFO "Detected OS: $OS $OS_VERSION ($OS_FAMILY family)"
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-build)
                SKIP_BUILD=true
                shift
                ;;
            --non-interactive)
                NON_INTERACTIVE=true
                shift
                ;;
            --control-plane)
                PROVIDED_CONTROL_PLANE="$2"
                shift 2
                ;;
            --jwt-secret)
                PROVIDED_JWT_SECRET="$2"
                shift 2
                ;;
            --hmac-key)
                PROVIDED_HMAC_KEY="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log WARN "Unknown option: $1"
                shift
                ;;
        esac
    done
}

show_help() {
    cat << EOF
Runic Firewall Management System - Installation Script
=========================================================

Usage:
  curl -sL https://raw.githubusercontent.com/runic/runic/main/install.sh | sudo bash
  sudo $0 [options]

Options:
  --skip-build           Skip building, assume binaries already exist
  --non-interactive      Run without prompts (use defaults)
  --control-plane URL    Control plane URL (default: localhost:8080)
  --jwt-secret SECRET    JWT secret (auto-generated if not provided)
  --hmac-key KEY         HMAC key for policy signing (auto-generated if not provided)
  -h, --help             Show this help message

Examples:
  # Interactive installation
  sudo $0

  # Non-interactive with custom values
  sudo $0 --non-interactive --control-plane 192.168.1.100:8080

  # Skip build (for development)
  sudo $0 --skip-build

EOF
}

# ============================================================================
# Installation Steps
# ============================================================================

install_dependencies() {
	log_section "Installing System Dependencies"

	local packages=("git" "build-essential" "sqlite3" "curl")

	if [ "$OS_FAMILY" = "debian" ]; then
		log INFO "Installing dependencies for Debian/Ubuntu..."

		# Update package list
		apt-get update -qq

		# Install packages
		apt-get install -y -qq "${packages[@]}" >> "$LOG_FILE" 2>&1

		# Install SQLite development files for CGO
		apt-get install -y -qq libsqlite3-dev >> "$LOG_FILE" 2>&1

		# Install Node.js 20.x from NodeSource (for frontend builds)
		log INFO "Installing Node.js 20.x from NodeSource..."
		curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
		apt-get install -y -qq nodejs >> "$LOG_FILE" 2>&1

	# Install Go 1.23+ from official source
	# Remove Ubuntu system golang-go package to avoid PATH conflicts
	apt-get remove -y golang-go >> "$LOG_FILE" 2>&1
	GO_VERSION="1.23.7"
		GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
		GO_URL="https://go.dev/dl/${GO_TAR}"
		log INFO "Installing Go ${GO_VERSION} from official source..."
		curl -sL "$GO_URL" -o "/tmp/${GO_TAR}" || { log ERROR "Failed to download Go"; exit 1; }
		rm -rf /usr/local/go # Remove any existing Go
		tar -C /usr/local -xzf "/tmp/${GO_TAR}" || { log ERROR "Failed to extract Go"; exit 1; }
		rm "/tmp/${GO_TAR}"
		# Add Go to PATH if not already there (prepend to take precedence over system Go)
		if ! grep -q '/usr/local/go/bin' /etc/profile; then
			echo 'export PATH=/usr/local/go/bin:$PATH' >> /etc/profile
		fi
		export PATH=/usr/local/go/bin:$PATH
		# Verify Go installation
		go version || { log ERROR "Go installation failed"; exit 1; }
		# Verify Go version is 1.23.x
		INSTALLED_GO_VERSION=$(go version | awk '{print $3}')
		if [[ "$INSTALLED_GO_VERSION" != go1.23* ]]; then
			log ERROR "Go version mismatch: expected go1.23.x, got $INSTALLED_GO_VERSION"
			exit 1
		fi
		log INFO "Verified Go version: $INSTALLED_GO_VERSION"

	elif [ "$OS_FAMILY" = "suse" ]; then
		log INFO "Installing dependencies for openSUSE..."

		# Refresh repositories
		zypper --quiet --non-interactive refresh

		# Install packages (excluding system go - we'll install from official source)
		zypper --quiet --non-interactive install -y \
			git \
			gcc \
			gcc-c++ \
			make \
			sqlite3 \
			sqlite3-devel \
			nodejs20 \
			npm20 >> "$LOG_FILE" 2>&1

		# Install Go 1.23+ from official source (same as Debian section)
		GO_VERSION="1.23.7"
		GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
		GO_URL="https://go.dev/dl/${GO_TAR}"
		log INFO "Installing Go ${GO_VERSION} from official source..."
		curl -sL "$GO_URL" -o "/tmp/${GO_TAR}" || { log ERROR "Failed to download Go"; exit 1; }
		rm -rf /usr/local/go # Remove any existing Go
		tar -C /usr/local -xzf "/tmp/${GO_TAR}" || { log ERROR "Failed to extract Go"; exit 1; }
		rm "/tmp/${GO_TAR}"
		# Add Go to PATH if not already there
		if ! grep -q '/usr/local/go/bin' /etc/profile; then
			echo 'export PATH=/usr/local/go/bin:$PATH' >> /etc/profile
		fi
		export PATH=/usr/local/go/bin:$PATH
		# Verify Go installation
		go version || { log ERROR "Go installation failed"; exit 1; }

	else
		log WARN "Unsupported OS family: $OS_FAMILY"
		log INFO "Please install the following packages manually: ${packages[*]}"
	fi

	# Verify installations
	local missing=()
	for cmd in git gcc make go sqlite3 npm; do
		if ! check_command "$cmd"; then
			missing+=("$cmd")
		fi
	done

	if [ ${#missing[@]} -eq 0 ]; then
		log SUCCESS "All dependencies installed successfully"
	else
		log ERROR "Missing dependencies: ${missing[*]}"
		exit 1
	fi
}

collect_configuration() {
    log_section "Collecting Configuration"
    
    # Control Plane URL
    if [ -n "$PROVIDED_CONTROL_PLANE" ]; then
        CONTROL_PLANE_URL="$PROVIDED_CONTROL_PLANE"
    else
        CONTROL_PLANE_URL=$(prompt_with_default "Control Plane URL (API server address)" "$DEFAULT_CONTROL_PLANE")
    fi
    log INFO "Control Plane URL: $CONTROL_PLANE_URL"
    
    # JWT Secret
    if [ -n "$PROVIDED_JWT_SECRET" ]; then
        JWT_SECRET="$PROVIDED_JWT_SECRET"
    else
        log INFO "JWT Secret: Using auto-generated secret"
        JWT_SECRET=$(generate_secret)
    fi
    
    # HMAC Key
    if [ -n "$PROVIDED_HMAC_KEY" ]; then
        HMAC_KEY="$PROVIDED_HMAC_KEY"
    else
        log INFO "HMAC Key: Using auto-generated key"
        HMAC_KEY=$(generate_secret)
    fi
    
    # Agent JWT Secret (for agent-server communication)
    if [ -n "$PROVIDED_JWT_SECRET" ]; then
        AGENT_JWT_SECRET="$PROVIDED_JWT_SECRET"
    else
        AGENT_JWT_SECRET=$(generate_secret)
    fi
    
    log SUCCESS "Configuration collected"
}

setup_directories() {
    log_section "Setting Up Directories"
    
    # Create installation directory
    if [ -d "$INSTALL_DIR" ]; then
        local response
        response=$(prompt_yes_no "Directory $INSTALL_DIR exists. Remove and recreate?" "no")
        if [ "$response" = "yes" ]; then
            log WARN "Removing existing installation at $INSTALL_DIR"
            safe_rm "$INSTALL_DIR"
        fi
    fi
    
    # Create directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$INSTALL_DIR/dist"
    
    log SUCCESS "Directories created at $INSTALL_DIR"
}

clone_repository() {
    log_section "Cloning Repository"

    # Ensure source directory exists
    mkdir -p "$SOURCE_DIR"

    # Check if repo already exists
    if [ -d "$SOURCE_DIR/.git" ]; then
        log INFO "Repository already exists, updating..."
        cd "$SOURCE_DIR"
        git pull origin "$REPO_BRANCH" >> "$LOG_FILE" 2>&1
    else
        log INFO "Cloning repository from $REPO_URL..."
        git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$SOURCE_DIR" >> "$LOG_FILE" 2>&1

        if [ $? -ne 0 ]; then
            log ERROR "Failed to clone repository"
            log INFO "Trying alternative: downloading source archive..."

            # Alternative: Download source
            local tmpdir tmpfile
            tmpdir=$(mktemp -d) || { log ERROR "Failed to create temp directory"; exit 1; }
            TEMP_DIRS+=("$tmpdir")
            tmpfile="$tmpdir/runic-${REPO_BRANCH}.tar.gz"
            curl -sL "https://github.com/ubenmackin/runic/archive/refs/heads/$REPO_BRANCH.tar.gz" -o "$tmpfile"

            if [ -f "$tmpfile" ]; then
                # Remove existing SOURCE_DIR contents if any
                safe_rm "$SOURCE_DIR"
                tar -xzf "$tmpfile" -C "$tmpdir"
                mv "$tmpdir/runic-$REPO_BRANCH" "$SOURCE_DIR" || { log ERROR "Failed to move extracted directory"; exit 1; }
            else
                log ERROR "Failed to download source"
                exit 1
            fi
        fi
    fi

    log SUCCESS "Repository cloned/updated"
}

build_binary() {
    if [ "$SKIP_BUILD" = true ]; then
        log INFO "Skipping build (--skip-build flag)"
        return 0
    fi

    log_section "Building Runic Server"

    cd "$SOURCE_DIR" || { log ERROR "Source directory not found"; exit 1; }

	# Check if Go modules are available
	if [ ! -f "go.mod" ]; then
		log ERROR "go.mod not found. Cannot build."
		exit 1
	fi

	# Build the web frontend if not already built
	if [ ! -d "internal/api/web/dist" ]; then
		log INFO "Building web frontend..."
		# Check if npm is installed
		if ! command -v npm &> /dev/null; then
			log ERROR "npm is not installed. Cannot build web frontend."
			exit 1
		fi
		cd web || { log ERROR "web directory not found"; exit 1; }
		npm install || { log ERROR "npm install failed"; exit 1; }
		npm run build || { log ERROR "npm run build failed"; exit 1; }
		cd .. || exit 1
		log SUCCESS "Web frontend built successfully"
	fi

	# Download Go dependencies
	log INFO "Downloading Go dependencies..."
	go mod download >> "$LOG_FILE" 2>&1

    # Build the server binary
    log INFO "Building runic-server with CGO enabled..."

    # Create dist directory in INSTALL_DIR
    mkdir -p "$INSTALL_DIR/dist"

    # Build with CGO for SQLite support
    CGO_ENABLED=1 go build -o "$INSTALL_DIR/dist/$BINARY_NAME" ./cmd/runic-server >> "$LOG_FILE" 2>&1

    if [ $? -ne 0 ]; then
        log ERROR "Build failed. Check $LOG_FILE for details."
        exit 1
    fi

    # Verify binary
    if [ -f "$INSTALL_DIR/dist/$BINARY_NAME" ]; then
        local size
        size=$(du -h "$INSTALL_DIR/dist/$BINARY_NAME" | cut -f1)
        log SUCCESS "Binary built successfully ($size)"
    else
        log ERROR "Binary not found after build"
        exit 1
    fi
}

create_system_user() {
    log_section "Creating System User"
    
    # Check if user exists
    if id "runic" >/dev/null 2>&1; then
        log INFO "User 'runic' already exists"
    else
        log INFO "Creating user 'runic'..."
        
        if [ "$OS_FAMILY" = "debian" ]; then
            useradd --system --no-create-home --shell /usr/sbin/nologin runic 2>> "$LOG_FILE"
        elif [ "$OS_FAMILY" = "suse" ]; then
            useradd --system --no-create-home --shell /sbin/nologin runic 2>> "$LOG_FILE"
        else
            useradd --system --no-create-home runic 2>> "$LOG_FILE"
        fi
        
        if [ $? -eq 0 ]; then
            log SUCCESS "User 'runic' created"
        else
            log ERROR "Failed to create user"
            exit 1
        fi
    fi
    
    # Set ownership
    chown -R runic:runic "$INSTALL_DIR" 2>> "$LOG_FILE"
    log SUCCESS "Ownership set to runic:runic"
}

initialize_database() {
    log_section "Initializing Database"
    
    cd "$INSTALL_DIR"
    
    # Check if database already exists
    if [ -f "$DATA_DIR/runic.db" ]; then
        local response
        response=$(prompt_yes_no "Database already exists. Recreate?" "no")
        if [ "$response" = "yes" ]; then
            rm -f "$DATA_DIR/runic.db"
        else
            log INFO "Using existing database"
            return 0
        fi
    fi
    
    # Create database by running the server once
    log INFO "Initializing SQLite database..."
    
    # Set environment variables for initial setup
    export RUNIC_HMAC_KEY="$HMAC_KEY"
    export RUNIC_JWT_SECRET="$JWT_SECRET"
    export RUNIC_AGENT_JWT_SECRET="$AGENT_JWT_SECRET"
    
    # Create database (the server will create it on startup)
    # Run briefly and check if database is created
    timeout 5 ./dist/$BINARY_NAME 2>&1 || true
    
    # Move database to data directory
    if [ -f "runic.db" ]; then
        mv runic.db "$DATA_DIR/runic.db"
        chown runic:runic "$DATA_DIR/runic.db"
        log SUCCESS "Database initialized at $DATA_DIR/runic.db"
    else
        log WARN "Database may not have been created. Will be created on first start."
    fi
}

install_systemd_service() {
    log_section "Installing Systemd Service"
    
    # Check if systemd is available
    if ! check_command systemctl; then
        log WARN "systemd not found. Skipping service installation."
        return 0
    fi
    
    # Check if service already exists
    if [ -f "/etc/systemd/system/$SERVICE_NAME.service" ]; then
        local response
        response=$(prompt_yes_no "Service already exists. Replace?" "no")
        if [ "$response" = "yes" ]; then
            systemctl stop "$SERVICE_NAME" 2>/dev/null || true
            systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        else
            log INFO "Keeping existing service"
            return 0
        fi
    fi
    
    # Create service file
    cat > "/tmp/$SERVICE_NAME.service" << EOF
[Unit]
Description=Runic Firewall Control Plane
Documentation=https://github.com/ubenmackin/runic
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=runic
Group=runic
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/dist/$BINARY_NAME
Restart=on-failure
RestartSec=10s

# Environment variables for secrets
Environment=RUNIC_HMAC_KEY=$HMAC_KEY
Environment=RUNIC_AGENT_JWT_SECRET=$AGENT_JWT_SECRET
Environment=RUNIC_JWT_SECRET=$JWT_SECRET
Environment=RUNIC_CONTROL_PLANE=$CONTROL_PLANE_URL
Environment=RUNIC_DB_PATH=$DATA_DIR/runic.db

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$DATA_DIR
ReadOnlyPaths=/etc/ssl/certs

# Resource limits
LimitNOFILE=65536
MemoryMax=512M

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=runic-server

[Install]
WantedBy=multi-user.target
EOF
    
    # Install service file
    cp "/tmp/$SERVICE_NAME.service" "/etc/systemd/system/$SERVICE_NAME.service"
    chmod 644 "/etc/systemd/system/$SERVICE_NAME.service"
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable service
    systemctl enable "$SERVICE_NAME"
    
    log SUCCESS "Systemd service installed"
}

start_service() {
    log_section "Starting Service"
    
    # Check if systemd is available
    if ! check_command systemctl; then
        log WARN "systemd not found. Cannot start service."
        return 0
    fi
    
    # Start service
    log INFO "Starting $SERVICE_NAME..."
    systemctl start "$SERVICE_NAME"
    
    if [ $? -eq 0 ]; then
        # Wait a moment for service to start
        sleep 2
        
        # Check status
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log SUCCESS "Service started successfully"
        else
            log WARN "Service started but may not be fully operational"
        fi
    else
        log ERROR "Failed to start service"
        log INFO "Check logs with: journalctl -u $SERVICE_NAME -f"
    fi
}

show_status() {
    log_section "Installation Complete!"
    
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Runic Firewall Management System Installed           ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${BOLD}Installation Details:${NC}"
    echo "  • Install Directory:  $INSTALL_DIR"
    echo "  • Data Directory:      $DATA_DIR"
    echo "  • Control Plane URL:  $CONTROL_PLANE_URL"
    echo "  • Log File:           $LOG_FILE"
    echo ""
    
    echo -e "${BOLD}Service Status:${NC}"
    if check_command systemctl; then
        systemctl status "$SERVICE_NAME" --no-pager -l || true
    fi
    echo ""
    
    echo -e "${BOLD}Next Steps:${NC}"
    echo "  1. Access the web interface:  http://$CONTROL_PLANE_URL"
    echo "  2. Login with admin credentials"
    echo "  3. Register your first firewall agent"
    echo ""
    
    echo -e "${BOLD}Useful Commands:${NC}"
    echo "  • View logs:     journalctl -u $SERVICE_NAME -f"
    echo "  • Restart:       sudo systemctl restart $SERVICE_NAME"
    echo "  • Stop:          sudo systemctl stop $SERVICE_NAME"
    echo "  • Check status:  sudo systemctl status $SERVICE_NAME"
    echo ""
    
    echo -e "${YELLOW}IMPORTANT: Save your secrets!${NC}"
    echo "  • JWT Secret:    $JWT_SECRET"
    echo "  • HMAC Key:      $HMAC_KEY"
    echo ""
    echo -e "${RED}Warning: Store these in a secure location!${NC}"
    echo ""
    
    log SUCCESS "Installation completed successfully"
}

# ============================================================================
# Main Installation Flow
# ============================================================================

main() {
    # Initialize log file
    touch "$LOG_FILE" 2>/dev/null || true
    
    # Parse arguments
    parse_arguments "$@"
    
    # Welcome banner
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     Runic Firewall Management System - Installer             ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Pre-installation checks
    check_root
    detect_os
    
    # Install dependencies
    install_dependencies
    
    # Get configuration
    collect_configuration
    
    # Setup directories
    setup_directories
    
    # Clone repository
    clone_repository
    
    # Build binary
    if [ "$SKIP_BUILD" = false ]; then
        build_binary
    fi
    
    # Create system user
    create_system_user
    
    # Initialize database
    initialize_database
    
    # Install systemd service
    install_systemd_service
    
    # Start service
    start_service
    
    # Show status
    show_status
}

# Run main function
main "$@"
