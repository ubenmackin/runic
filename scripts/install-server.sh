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
CERT_DIR="${INSTALL_DIR}/cert"
SOURCE_DIR="/opt/runic/src"
LOG_FILE="/var/log/runic-install.log"
BINARY_NAME="runic-server"
SERVICE_NAME="runic-server"

# Defaults
DEFAULT_CONTROL_PLANE="localhost:60443"
RUNIC_PORT="${RUNIC_PORT:-60443}"

REPO_URL="https://github.com/ubenmackin/runic.git"
REPO_BRANCH="main"

# Flags
SKIP_BUILD=false
NON_INTERACTIVE=false
PROVIDED_CONTROL_PLANE=""
PROVIDED_JWT_SECRET=""
COMMIT_REF=""

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

	# Validate path matches expected pattern OR is the base install directory
	# Using case for glob-style matching
	case "$path" in
	$pattern)
		log INFO "Removing: $path"
		rm -rf "$path"
		return $?
		;;
	$INSTALL_DIR)
		# Allow removing the base install directory
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
            read -p "$prompt [Y/n]: " response < /dev/tty
        else
            read -p "$prompt [y/N]: " response < /dev/tty
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
    
    read -p "$prompt [$default]: " response < /dev/tty
    if [ -z "$response" ]; then
        echo "$default"
    else
        echo "$response"
    fi
}

generate_secret() {
    # Check if openssl is available
    command -v openssl >/dev/null 2>&1 || { log ERROR "openssl is required but not installed"; exit 1; }

    local secret
    secret=$(openssl rand -hex 32)

    # Validate secret length (should be 64 hex characters)
    if [ ${#secret} -ne 64 ]; then
        log ERROR "Generated secret is not 64 characters: ${#secret}"
        exit 1
    fi

    echo "$secret"
}

generate_self_signed_cert() {
    log_section "Generating TLS Certificate"

    # Check if openssl is available
    command -v openssl >/dev/null 2>&1 || { log ERROR "openssl is required for certificate generation"; exit 1; }

    # Check if certificates already exist
    if [ -f "$CERT_DIR/key.pem" ] && [ -f "$CERT_DIR/cert.pem" ]; then
        log INFO "TLS certificates already exist at $CERT_DIR"
        local response
        response=$(prompt_yes_no "Regenerate certificates?" "no")
        if [ "$response" = "no" ]; then
            log INFO "Using existing certificates"
            return 0
        fi
        log WARN "Removing existing certificates..."
        rm -f "$CERT_DIR/key.pem" "$CERT_DIR/cert.pem"
    fi

    # Create certificate directory with proper ownership
    if [ ! -d "$CERT_DIR" ]; then
        log INFO "Creating certificate directory: $CERT_DIR"
        mkdir -p "$CERT_DIR" || { log ERROR "Failed to create certificate directory"; exit 1; }
    fi

    # Set ownership of certificate directory
    if ! chown -R runic:runic "$CERT_DIR" 2>> "$LOG_FILE"; then
        log ERROR "Failed to set ownership on certificate directory"
        exit 1
    fi

    # Generate 4096-bit RSA private key
    log INFO "Generating 4096-bit RSA private key..."
    if ! openssl genrsa -out "$CERT_DIR/key.pem" 4096 2>> "$LOG_FILE"; then
        log ERROR "Failed to generate private key"
        exit 1
    fi

    # Set strict permissions on private key (640 - readable by owner and group)
    if ! chmod 640 "$CERT_DIR/key.pem"; then
        log ERROR "Failed to set permissions on private key"
        exit 1
    fi

    # Generate self-signed certificate valid for 365 days
    log INFO "Generating self-signed certificate valid for 365 days..."
    if ! openssl req -new -x509 -key "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
        -days 365 -subj "/CN=localhost/O=Runic/C=US" 2>> "$LOG_FILE"; then
        log ERROR "Failed to generate certificate"
        rm -f "$CERT_DIR/key.pem"
        exit 1
    fi

    # Set permissions on certificate (644 - readable by all)
    if ! chmod 644 "$CERT_DIR/cert.pem"; then
        log ERROR "Failed to set permissions on certificate"
        rm -f "$CERT_DIR/key.pem"
        exit 1
    fi

    # Verify certificates were created
    if [ ! -f "$CERT_DIR/key.pem" ] || [ ! -f "$CERT_DIR/cert.pem" ]; then
        log ERROR "Certificates were not created successfully"
        exit 1
    fi

    # Set ownership again to ensure runic group has access
    chown runic:runic "$CERT_DIR/key.pem" "$CERT_DIR/cert.pem" 2>> "$LOG_FILE" || {
        log ERROR "Failed to set ownership on certificate files"
        exit 1
    }

    log SUCCESS "TLS certificates generated successfully:"
    log SUCCESS "  • Private key:  $CERT_DIR/key.pem (640, runic:runic)"
    log SUCCESS "  • Certificate:   $CERT_DIR/cert.pem (644, runic:runic)"
}

validate_secret() {
	local secret_name="$1"
	local secret_value="$2"

	# Check if secret is empty
	if [ -z "$secret_value" ]; then
		log ERROR "Secret $secret_name is empty"
		return 1
	fi

	# Check minimum length (at least 32 characters)
	if [ ${#secret_value} -lt 32 ]; then
		log ERROR "Secret $secret_name is too short (minimum 32 characters, got ${#secret_value})"
		return 1
	fi

	return 0
}

validate_runic_port() {
	# Validate RUNIC_PORT is numeric and in valid range (1-65535)
	if ! [[ "$RUNIC_PORT" =~ ^[0-9]+$ ]]; then
		log ERROR "RUNIC_PORT must be numeric, got: $RUNIC_PORT"
		exit 1
	fi
	if [ "$RUNIC_PORT" -lt 1 ] || [ "$RUNIC_PORT" -gt 65535 ]; then
		log ERROR "RUNIC_PORT must be between 1 and 65535, got: $RUNIC_PORT"
		exit 1
	fi
    log INFO "Validated RUNIC_PORT: $RUNIC_PORT"
}

# ============================================================================
# Storing Secrets in Database
# ============================================================================

generate_secrets() {
    log INFO "Generating secrets..."
    
    local jwt_secret agent_jwt_secret
    
    # Generate or use provided JWT secret
    if [ -n "$PROVIDED_JWT_SECRET" ]; then
        # Validate provided secret
        if ! validate_secret "PROVIDED_JWT_SECRET" "$PROVIDED_JWT_SECRET"; then
            log ERROR "Provided JWT secret is invalid"
            exit 1
        fi
        jwt_secret="$PROVIDED_JWT_SECRET"
        log INFO "Using provided JWT secret"
    else
        jwt_secret=$(generate_secret) || { log ERROR "Failed to generate JWT secret"; exit 1; }
        log INFO "Generated new JWT secret"
    fi
    
    # Always generate new agent JWT secret (will preserve in DB if exists)
    agent_jwt_secret=$(generate_secret) || { log ERROR "Failed to generate agent JWT secret"; exit 1; }
    log INFO "Generated new RUNIC_AGENT_JWT_SECRET"
    
    # Set variables for use in script
    JWT_SECRET="$jwt_secret"
    AGENT_JWT_SECRET="$agent_jwt_secret"
    
    log SUCCESS "Secrets generated successfully"
}

store_secrets_in_db() {
    log_section "Storing Secrets in Database"
    
    local db_path="$DATA_DIR/runic.db"
    
    # Check if jwt_secret already exists in database (preserve existing)
    local existing_jwt_secret
    existing_jwt_secret=$(sqlite3 "$db_path" "SELECT value FROM system_config WHERE key='jwt_secret';" 2>/dev/null || echo "")
    
    # Determine which jwt_secret to use (priority: provided > DB existing > newly generated)
    if [ -n "$PROVIDED_JWT_SECRET" ]; then
        # Provided secret takes precedence
        log INFO "Using provided JWT secret"
        JWT_SECRET="$PROVIDED_JWT_SECRET"
    elif [ -n "$existing_jwt_secret" ] && validate_secret "existing jwt_secret" "$existing_jwt_secret"; then
        # Preserve existing valid jwt_secret from database
        log INFO "Preserving existing jwt_secret from database"
        JWT_SECRET="$existing_jwt_secret"
    else
        # Use newly generated JWT_SECRET
        log INFO "Using newly generated jwt_secret"
    fi
    
    # Check if agent_jwt_secret already exists in database (preserve existing)
    local existing_agent_secret
    existing_agent_secret=$(sqlite3 "$db_path" "SELECT value FROM system_config WHERE key='agent_jwt_secret';" 2>/dev/null || echo "")
    
    if [ -n "$existing_agent_secret" ] && validate_secret "existing RUNIC_AGENT_JWT_SECRET" "$existing_agent_secret"; then
        log INFO "Preserving existing RUNIC_AGENT_JWT_SECRET from database"
        AGENT_JWT_SECRET="$existing_agent_secret"
    else
        log INFO "Using newly generated RUNIC_AGENT_JWT_SECRET"
    fi
    
    # Store jwt_secret in database
    log INFO "Storing jwt_secret in system_config..."
    sqlite3 "$db_path" "INSERT OR REPLACE INTO system_config (key, value) VALUES ('jwt_secret', '$JWT_SECRET');" 2>> "$LOG_FILE" || {
        log ERROR "Failed to store jwt_secret in system_config"
        exit 1
    }
    
    # Store agent_jwt_secret in database
    log INFO "Storing agent_jwt_secret in system_config..."
    sqlite3 "$db_path" "INSERT OR REPLACE INTO system_config (key, value) VALUES ('agent_jwt_secret', '$AGENT_JWT_SECRET');" 2>> "$LOG_FILE" || {
        log ERROR "Failed to store agent_jwt_secret in system_config"
        exit 1
    }
    
    log SUCCESS "Secrets stored in database successfully"
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
            --commit)
                COMMIT_REF="$2"
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
  --control-plane URL    Control plane URL (default: localhost:60443)
  --jwt-secret SECRET    JWT secret (auto-generated if not provided)
  --commit SHA           Install from a specific git commit SHA (e.g., e94c2e3)
  -h, --help             Show this help message

Examples:
  # Interactive installation
  sudo $0

  # Non-interactive with custom values
  sudo $0 --non-interactive --control-plane 192.168.1.100:60443

  # Skip build (for development)
  sudo $0 --skip-build

  # Install from a specific commit
  sudo $0 --commit e94c2e3

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

		# Install Go 1.25+ from official source
		# Remove Ubuntu system golang-go package to avoid PATH conflicts
		apt-get remove -y golang-go >> "$LOG_FILE" 2>&1
		GO_VERSION="1.25.8"
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
		# Verify Go version is 1.25.x
		INSTALLED_GO_VERSION=$(go version | awk '{print $3}')
		if [[ "$INSTALLED_GO_VERSION" != go1.25* ]]; then
			log ERROR "Go version mismatch: expected go1.25.x, got $INSTALLED_GO_VERSION"
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

		# Install Go 1.25+ from official source (same as Debian section)
		GO_VERSION="1.25.8"
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

	# Logs database path
	LOGS_DB_PATH=$(prompt_with_default "Enter logs database path" "$DATA_DIR/logs.db")
	log INFO "Logs database path: $LOGS_DB_PATH"

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
    
    # Create directories with error handling
    if ! mkdir -p "$INSTALL_DIR"; then
        log ERROR "Failed to create installation directory: $INSTALL_DIR"
        exit 1
    fi
    
    if ! mkdir -p "$DATA_DIR"; then
        log ERROR "Failed to create data directory: $DATA_DIR"
        exit 1
    fi
    
    if ! mkdir -p "$INSTALL_DIR/dist"; then
        log ERROR "Failed to create dist directory: $INSTALL_DIR/dist"
        exit 1
    fi

    if ! mkdir -p "$INSTALL_DIR/downloads"; then
        log ERROR "Failed to create downloads directory: $INSTALL_DIR/downloads"
        exit 1
    fi

    log SUCCESS "Directories created at $INSTALL_DIR"
}

clone_repository() {
    log_section "Cloning Repository"

    # Ensure source directory exists
    mkdir -p "$SOURCE_DIR"

    # Check if repo already exists
    if [ -d "$SOURCE_DIR/.git" ]; then
        log INFO "Repository already exists, updating..."
        # Fix git ownership error by marking the directory as safe
        git config --global --add safe.directory "$SOURCE_DIR" 2>/dev/null || true

        cd "$SOURCE_DIR"
        
        if [ -n "$COMMIT_REF" ]; then
            # Fetch and checkout specific commit
            log INFO "Checking out commit: $COMMIT_REF"
            git fetch origin >> "$LOG_FILE" 2>&1 || { log ERROR "Failed to fetch from origin"; exit 1; }
            git checkout "$COMMIT_REF" >> "$LOG_FILE" 2>&1 || { log ERROR "Failed to checkout commit $COMMIT_REF"; exit 1; }
        else
            # Fetch latest changes and hard reset to origin branch
            git fetch origin "$REPO_BRANCH" >> "$LOG_FILE" 2>&1 || { log ERROR "Failed to fetch from origin"; exit 1; }
            git reset --hard "origin/$REPO_BRANCH" >> "$LOG_FILE" 2>&1 || { log ERROR "Failed to reset to origin/$REPO_BRANCH"; exit 1; }
        fi
    else
        if [ -n "$COMMIT_REF" ]; then
            # Full clone (no --depth 1) to access arbitrary commits
            log INFO "Cloning repository from $REPO_URL for commit $COMMIT_REF..."
            git clone "$REPO_URL" "$SOURCE_DIR" >> "$LOG_FILE" 2>&1

            if [ $? -ne 0 ]; then
                log ERROR "Failed to clone repository"
                exit 1
            fi

            cd "$SOURCE_DIR"
            log INFO "Checking out commit: $COMMIT_REF"
            git checkout "$COMMIT_REF" >> "$LOG_FILE" 2>&1 || { log ERROR "Failed to checkout commit $COMMIT_REF"; exit 1; }
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

	# Version info for build (captured BEFORE any npm/go steps to avoid false "-dirty" suffix)
	VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
	COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
	BUILT_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

	# Check if Go modules are available
	if [ ! -f "go.mod" ]; then
		log ERROR "go.mod not found. Cannot build."
		exit 1
	fi

	# Build the web frontend (always rebuild to pick up changes)
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

	# Download Go dependencies
	log INFO "Downloading Go dependencies..."
	go mod download >> "$LOG_FILE" 2>&1

	# Build the server binary
	log INFO "Building runic-server with CGO enabled..."

	# Create dist directory in INSTALL_DIR
	mkdir -p "$INSTALL_DIR/dist"

	# Build with CGO for SQLite support and inject version info via ldflags
	CGO_ENABLED=1 go build -ldflags="-X runic/internal/common/version.Version=$VERSION -X runic/internal/common/version.Commit=$COMMIT -X runic/internal/common/version.BuiltAt=$BUILT_AT" -buildvcs=false -o "$INSTALL_DIR/dist/$BINARY_NAME" ./cmd/runic-server >> "$LOG_FILE" 2>&1

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

build_agent_binaries() {
	if [ "$SKIP_BUILD" = true ]; then
		log INFO "Skipping agent build (--skip-build flag)"
		return 0
	fi

	log_section "Building Runic Agent Binaries"

cd "$SOURCE_DIR" || { log ERROR "Source directory not found"; exit 1; }

  # Capture version information before any build steps
  VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
  COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILT_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
AGENT_VERSION=$(cat .agent-version 2>/dev/null || echo "dev")

# Create downloads directory
	mkdir -p "$INSTALL_DIR/downloads"

	# Build for each architecture
	local arches=("amd64" "arm" "armv6" "arm64")
	local built_count=0

	for arch in "${arches[@]}"; do
		log INFO "Building runic-agent for $arch..."

if [ "$arch" = "armv6" ]; then
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -ldflags="-X runic/internal/agent/core.Version=$AGENT_VERSION -X runic/internal/common/version.Commit=$COMMIT -X runic/internal/common/version.BuiltAt=$BUILT_AT" -a -buildvcs=false -o "$INSTALL_DIR/downloads/runic-agent-armv6" ./cmd/runic-agent >> "$LOG_FILE" 2>&1
	else
		CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -ldflags="-X runic/internal/agent/core.Version=$AGENT_VERSION -X runic/internal/common/version.Commit=$COMMIT -X runic/internal/common/version.BuiltAt=$BUILT_AT" -a -buildvcs=false -o "$INSTALL_DIR/downloads/runic-agent-$arch" ./cmd/runic-agent >> "$LOG_FILE" 2>&1
		fi

		if [ $? -ne 0 ]; then
			log ERROR "Failed to build runic-agent for $arch. Check $LOG_FILE for details."
			exit 1
		fi

		if [ -f "$INSTALL_DIR/downloads/runic-agent-$arch" ]; then
			local size
			size=$(du -h "$INSTALL_DIR/downloads/runic-agent-$arch" | cut -f1)
			log SUCCESS "runic-agent-$arch built successfully ($size)"
			((built_count++))
		else
			log ERROR "runic-agent-$arch not found after build"
			exit 1
		fi
	done

	# Copy service file
	if [ -f "$SOURCE_DIR/scripts/runic-agent.service" ]; then
		cp "$SOURCE_DIR/scripts/runic-agent.service" "$INSTALL_DIR/downloads/" || { log ERROR "Failed to copy runic-agent.service"; exit 1; }
		log SUCCESS "runic-agent.service copied to downloads directory"
	else
		log ERROR "runic-agent.service not found at $SOURCE_DIR/scripts/runic-agent.service"
		exit 1
	fi

	# Set permissions on binaries (755) and service file (644)
	chmod 755 "$INSTALL_DIR/downloads/runic-agent-"* || { log ERROR "Failed to set permissions on agent binaries"; exit 1; }
	chmod 644 "$INSTALL_DIR/downloads/runic-agent.service" || { log ERROR "Failed to set permissions on service file"; exit 1; }

	log SUCCESS "All agent binaries built successfully ($built_count architectures)"
}

create_system_user() {
    log_section "Creating System User"
    
    # Check if user exists
    if id "runic" >/dev/null 2>&1; then
        log INFO "User 'runic' already exists"
    else
        log INFO "Creating user 'runic'..."
        
        if [ "$OS_FAMILY" = "debian" ]; then
            useradd --system --no-create-home --shell /usr/sbin/nologin runic 2>> "$LOG_FILE" || { log ERROR "Failed to create user 'runic'"; exit 1; }
        elif [ "$OS_FAMILY" = "suse" ]; then
            useradd --system --no-create-home --shell /sbin/nologin runic 2>> "$LOG_FILE" || { log ERROR "Failed to create user 'runic'"; exit 1; }
        else
            useradd --system --no-create-home runic 2>> "$LOG_FILE" || { log ERROR "Failed to create user 'runic'"; exit 1; }
        fi
        
        log SUCCESS "User 'runic' created"
    fi
    
    # Set ownership with error handling
    if ! chown -R runic:runic "$INSTALL_DIR" 2>> "$LOG_FILE"; then
        log ERROR "Failed to set ownership on $INSTALL_DIR"
        exit 1
    fi
    
    log SUCCESS "Ownership set to runic:runic"
}

initialize_database() {
    log_section "Initializing Database"
    
    cd "$INSTALL_DIR" || { log ERROR "Failed to change to installation directory"; exit 1; }
    
    # Check if database already exists
    if [ -f "$DATA_DIR/runic.db" ]; then
        local response
        response=$(prompt_yes_no "Database already exists. Recreate?" "no")
        if [ "$response" = "yes" ]; then
            if ! rm -f "$DATA_DIR/runic.db"; then
                log ERROR "Failed to remove existing database"
                exit 1
            fi
            # Ensure DATA_DIR still exists after database removal
            if [ ! -d "$DATA_DIR" ]; then
                log INFO "Recreating DATA_DIR: $DATA_DIR"
                mkdir -p "$DATA_DIR"
                chown runic:runic "$DATA_DIR" 2>/dev/null || true
            fi
        else
            log INFO "Using existing database"
            return 0
        fi
    fi
    
    # Create database by running the server once
    log INFO "Initializing SQLite database..."
    
    # Set environment variables for initial setup
    export RUNIC_JWT_SECRET="$JWT_SECRET"
    export RUNIC_AGENT_JWT_SECRET="$AGENT_JWT_SECRET"
    export RUNIC_DB_PATH="$DATA_DIR/runic.db"
    export RUNIC_CERT_FILE="$CERT_DIR/cert.pem"
    export RUNIC_KEY_FILE="$CERT_DIR/key.pem"
    
    # === DEBUG: Log diagnostic information before running server ===
    log DEBUG "=== Server Startup Diagnostics ==="
    log DEBUG "Working directory: $(pwd)"
    log DEBUG "Binary path: $INSTALL_DIR/dist/$BINARY_NAME"
    log DEBUG "Binary exists: $(test -f "./dist/$BINARY_NAME" && echo "YES" || echo "NO")"
    log DEBUG "Binary executable: $(test -x "./dist/$BINARY_NAME" && echo "YES" || echo "NO")"
    log DEBUG "Binary owner: $(ls -la ./dist/$BINARY_NAME 2>/dev/null | awk '{print $3":"$4}' || echo "N/A")"
    log DEBUG "DATA_DIR: $DATA_DIR"
    log DEBUG "DATA_DIR exists: $(test -d "$DATA_DIR" && echo "YES" || echo "NO")"
    log DEBUG "DATA_DIR writable: $(test -w "$DATA_DIR" && echo "YES" || echo "NO")"
    log DEBUG "DB path: $DATA_DIR/runic.db"
    log DEBUG "DB exists: $(test -f "$DATA_DIR/runic.db" && echo "YES" || echo "NO")"
    log DEBUG "CERT_FILE: $CERT_DIR/cert.pem"
    log DEBUG "CERT_FILE exists: $(test -f "$CERT_DIR/cert.pem" && echo "YES" || echo "NO")"
    log DEBUG "KEY_FILE: $CERT_DIR/key.pem"
    log DEBUG "KEY_FILE exists: $(test -f "$CERT_DIR/key.pem" && echo "YES" || echo "NO")"
    log DEBUG "RUNIC_JWT_SECRET set: $(test -n "$RUNIC_JWT_SECRET" && echo "YES (${#RUNIC_JWT_SECRET} chars)" || echo "NO")"
    log DEBUG "RUNIC_AGENT_JWT_SECRET set: $(test -n "$RUNIC_AGENT_JWT_SECRET" && echo "YES (${#RUNIC_AGENT_JWT_SECRET} chars)" || echo "NO")"
    log DEBUG "User context: $(whoami)"
    log DEBUG "=== End Diagnostics ==="
    
    # Create database (the server will create it on startup)
    # Run briefly and check if database is created
    # Capture full output to temp file for debugging
    local server_output_file
    server_output_file=$(mktemp)
    trap "rm -f '$server_output_file'" RETURN
    
    log DEBUG "Starting server to initialize database..."
    log DEBUG "Command: timeout 5 ./dist/$BINARY_NAME"
    log DEBUG "--- Server Output Start ---"
    
    # Run server and capture ALL output
    local server_exit_code=0
    timeout 5 ./dist/$BINARY_NAME 2>&1 | tee "$server_output_file" || server_exit_code=$?
    
    log DEBUG "--- Server Output End ---"
    log DEBUG "Server exit code: $server_exit_code"
    
    # Check if the success message appeared
    if grep -q "Starting Runic HTTPS server" "$server_output_file"; then
        log DEBUG "SUCCESS: Found 'Starting Runic HTTPS server' in output"
    else
        log ERROR "Failed to initialize database"
        log ERROR "Server exit code: $server_exit_code"
        log ERROR "Full server output:"
        while IFS= read -r line; do
            log ERROR "  $line"
        done < "$server_output_file"
        log ERROR "Database path: $DATA_DIR/runic.db"
        log ERROR "DATA_DIR exists: $(test -d "$DATA_DIR" && echo "yes" || echo "no")"
        log ERROR "DATA_DIR writable: $(test -w "$DATA_DIR" && echo "yes" || echo "no")"
        rm -f "$server_output_file"
        exit 1
    fi
    
    rm -f "$server_output_file"
    
    # Verify database was created
    if [ -f "$DATA_DIR/runic.db" ]; then
        if ! chown runic:runic "$DATA_DIR/runic.db"; then
            log ERROR "Failed to set ownership on database"
            exit 1
        fi
        chown -f runic:runic "$DATA_DIR"/runic.db-* 2>/dev/null || true
	log SUCCESS "Database initialized at $DATA_DIR/runic.db"

	# Store control plane port in system_config
	log INFO "Storing control plane port ($RUNIC_PORT) in system configuration..."
	sqlite3 "$DATA_DIR/runic.db" "INSERT OR REPLACE INTO system_config (key, value) VALUES ('control_plane_port', '$RUNIC_PORT');" 2>> "$LOG_FILE" || {
		log ERROR "Failed to store control plane port in system_config"
		exit 1
	}
	log SUCCESS "Control plane port stored in system configuration"

	# Store instance URL (constructed from CONTROL_PLANE_URL and port)
	INSTANCE_URL="https://$CONTROL_PLANE_URL:$RUNIC_PORT"
	log INFO "Storing instance URL ($INSTANCE_URL) in system configuration..."
	sqlite3 "$DATA_DIR/runic.db" "INSERT OR REPLACE INTO system_config (key, value) VALUES ('instance_url', '$INSTANCE_URL');" 2>> "$LOG_FILE" || {
		log ERROR "Failed to store instance_url in system_config"
		exit 1
	}
	log SUCCESS "Instance URL stored in system configuration"
else
        log ERROR "Database was not created despite server starting successfully"
        log ERROR "Database path: $DATA_DIR/runic.db"
        exit 1
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
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        response=$(prompt_yes_no "Service already exists. Replace?" "no")
        if [ "$response" = "yes" ]; then
            systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        else
            log INFO "Keeping existing service file, starting new binary"
            return 0
        fi
    fi
    
    # Create service file with error handling
    if ! cat > "/tmp/$SERVICE_NAME.service" << EOF
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

# Environment variables for configuration
Environment=RUNIC_CONTROL_PLANE=$CONTROL_PLANE_URL
Environment=RUNIC_DB_PATH=$DATA_DIR/runic.db
Environment=RUNIC_LOGS_DB_PATH=$LOGS_DB_PATH
Environment=RUNIC_CERT_FILE=$CERT_DIR/cert.pem
Environment=RUNIC_KEY_FILE=$CERT_DIR/key.pem
Environment=RUNIC_PORT=$RUNIC_PORT
Environment=RUNIC_DOWNLOADS_DIR=$INSTALL_DIR/downloads

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$DATA_DIR $CERT_DIR $INSTALL_DIR/downloads
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
    then
        log ERROR "Failed to create service file"
        exit 1
    fi
    
    # Install service file with error handling
    if ! cp "/tmp/$SERVICE_NAME.service" "/etc/systemd/system/$SERVICE_NAME.service"; then
        log ERROR "Failed to copy service file to systemd directory"
        exit 1
    fi
    
    if ! chmod 644 "/etc/systemd/system/$SERVICE_NAME.service"; then
        log ERROR "Failed to set permissions on service file"
        exit 1
    fi
    
    # Reload systemd
    if ! systemctl daemon-reload; then
        log ERROR "Failed to reload systemd"
        exit 1
    fi
    
    # Enable service
    if ! systemctl enable "$SERVICE_NAME"; then
        log ERROR "Failed to enable service"
        exit 1
    fi
    
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
    echo "  • Cert Directory:     $CERT_DIR"
    echo "  • Control Plane URL:  $CONTROL_PLANE_URL"
    echo "  • Server Port:        $RUNIC_PORT (HTTPS)"
    echo "  • Log File:           $LOG_FILE"
    echo ""

    echo -e "${BOLD}Service Status:${NC}"
    if check_command systemctl; then
        systemctl status "$SERVICE_NAME" --no-pager -l || true
    fi
    echo ""

    echo -e "${BOLD}Next Steps:${NC}"
    echo "  1. Access the web interface:  https://$CONTROL_PLANE_URL:$RUNIC_PORT"
    echo "  2. Login with admin credentials"
    echo "  3. Register your first firewall agent"
    echo ""

    echo -e "${BOLD}Useful Commands:${NC}"
    echo "  • View logs:     journalctl -u $SERVICE_NAME -f"
    echo "  • Restart:       sudo systemctl restart $SERVICE_NAME"
    echo "  • Stop:          sudo systemctl stop $SERVICE_NAME"
    echo "  • Check status:  sudo systemctl status $SERVICE_NAME"
    echo ""

    echo -e "${BOLD}TLS Certificate Information:${NC}"
    echo "  • Certificate:   $CERT_DIR/cert.pem"
    echo "  • Private Key:   $CERT_DIR/key.pem"
    echo ""
    echo -e "${YELLOW}⚠ Self-Signed Certificate Warning:${NC}"
    echo -e "${YELLOW}  This installation uses a self-signed certificate. Your browser may show${NC}"
    echo -e "${YELLOW}  a security warning. This is expected and safe for this deployment.${NC}"
    echo ""
    echo -e "${YELLOW}  To proceed in most browsers:${NC}"
    echo -e "${YELLOW}  1. Click 'Advanced' or 'Show Details'${NC}"
    echo -e "${YELLOW}  2. Click 'Proceed to ...' or 'Accept Risk'${NC}"
    echo -e "${YELLOW}  3. You will only need to do this once (or until cert expires)${NC}"
    echo ""

    echo -e "${BOLD}Using Custom Certificates:${NC}"
    echo "  To use your own TLS certificates instead of the self-signed ones:"
    echo ""
    echo "  1. Place your certificate at: $CERT_DIR/cert.pem"
    echo "  2. Place your private key at:  $CERT_DIR/key.pem"
    echo "  3. Set proper permissions:"
    echo "     sudo chown runic:runic $CERT_DIR/*.pem"
    echo "     sudo chmod 644 $CERT_DIR/cert.pem"
    echo "     sudo chmod 640 $CERT_DIR/key.pem"
    echo "  4. Restart the service:"
    echo "     sudo systemctl restart $SERVICE_NAME"
    echo ""

    echo -e "${GREEN}✓ Secrets: Configured${NC}"
    echo -e "${YELLOW}  Secrets are stored in database at: $DATA_DIR/runic.db${NC}"
    echo -e "${YELLOW}  Keep your database backed up!${NC}"
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

	# Validate RUNIC_PORT early (after log function is available)
	validate_runic_port

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

    # Setup directories
    setup_directories

    # Generate secrets (before database init, but after directories exist)
    generate_secrets
    
    # Clone repository
    clone_repository
    
    # Build binary
    if [ "$SKIP_BUILD" = false ]; then
        build_binary
        build_agent_binaries
    fi
    
    # Create system user
    create_system_user

    # Generate TLS certificate
    generate_self_signed_cert

    # Initialize database
    initialize_database

    # Store secrets in database (after database exists)
    store_secrets_in_db

    # Install systemd service
    install_systemd_service
    
    # Start service
    start_service
    
    # Show status
    show_status
}

# Run main function
main "$@"
