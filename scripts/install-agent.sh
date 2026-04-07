#!/bin/bash
set -e

ARCH=$(uname -m)
case $ARCH in
x86_64) AGENT_ARCH="amd64" ;;
aarch64) AGENT_ARCH="arm64" ;;
armv7l) AGENT_ARCH="arm" ;;
armv6l) AGENT_ARCH="armv6" ;;
*) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

# Install ipset if available (non-fatal)
if ! command -v ipset &>/dev/null; then
    echo "Installing ipset..."
    if command -v apt-get &>/dev/null; then
        apt-get install -y ipset 2>/dev/null || echo "Warning: Failed to install ipset via apt-get"
    elif command -v yum &>/dev/null; then
        yum install -y ipset 2>/dev/null || echo "Warning: Failed to install ipset via yum"
    elif command -v apk &>/dev/null; then
        apk add ipset 2>/dev/null || echo "Warning: Failed to install ipset via apk"
    else
        echo "Warning: No supported package manager found for ipset installation"
    fi
else
    echo "ipset already installed."
fi

CONTROL_PLANE_URL="${1:-}"
REGISTRATION_TOKEN="${2:-}"
if [ -z "$CONTROL_PLANE_URL" ]; then
echo "Usage: install-agent.sh <control-plane-url> <registration-token>"
echo "Example: install-agent.sh https://runic.home.lan:60443 my-token-abc123"
exit 1
fi

# Check if service is running and stop it for upgrade
if systemctl is-active --quiet runic-agent 2>/dev/null; then
echo "Stopping existing runic-agent service..."
systemctl stop runic-agent
fi

BINARY_URL="${CONTROL_PLANE_URL}/downloads/runic-agent-${AGENT_ARCH}"

echo "Downloading runic-agent for ${AGENT_ARCH}..."
curl -fsSL -o /usr/local/bin/runic-agent "$BINARY_URL"
chmod +x /usr/local/bin/runic-agent

# Create config directory if it doesn't exist
mkdir -p /etc/runic-agent
chmod 700 /etc/runic-agent

# Create log directory
mkdir -p /var/log/runic
chmod 755 /var/log/runic

# Install rsyslog config for firewall logs
if [ -d /etc/rsyslog.d ]; then
    cat > /etc/rsyslog.d/30-runic-firewall.conf << 'EOF'
# Runic Firewall - Route firewall log messages to dedicated file
:msg,contains,"[RUNIC" /var/log/runic/firewall.log
& stop
EOF
    chmod 644 /etc/rsyslog.d/30-runic-firewall.conf
    systemctl restart rsyslog 2>/dev/null || true
fi

# Detect OS type from /etc/os-release
detect_os() {
	if [ -f /etc/os-release ]; then
		. /etc/os-release
		# Normalize OS ID for edge cases (e.g., opensuse-leap -> opensuse, opensuse-tumbleweed -> opensuse)
		case "$ID" in
			opensuse*|sle*)
				echo "opensuse"
				;;
			*)
				echo "$ID"
				;;
		esac
	else
		echo "unknown"
	fi
}

# Disable iptables persistence services to prevent conflicts with runic's firewall management
# Different distributions use different services for iptables persistence
disable_iptables_services() {
	OS_TYPE=$(detect_os)
	echo "Detected OS: $OS_TYPE"

	case "$OS_TYPE" in
		ubuntu|debian|linuxmint|pop)
			echo "Disabling Debian/Ubuntu iptables persistence services..."
			for service in netfilter-persistent iptables-persistent; do
				if systemctl is-active --quiet "$service" 2>/dev/null || \
				systemctl is-enabled --quiet "$service" 2>/dev/null; then
					echo " -> Stopping and disabling $service..."
					systemctl stop "$service" 2>/dev/null || true
					systemctl disable "$service" 2>/dev/null || true
					systemctl mask "$service" 2>/dev/null || true
				fi
			done
			;;
		arch|archarm|manjaro|endeavouros)
			echo "Disabling Arch Linux iptables services..."
			for service in iptables ip6tables; do
				if systemctl is-active --quiet "$service" 2>/dev/null || \
				systemctl is-enabled --quiet "$service" 2>/dev/null; then
					echo " -> Stopping and disabling $service.service..."
					systemctl stop "$service" 2>/dev/null || true
					systemctl disable "$service" 2>/dev/null || true
					systemctl mask "$service" 2>/dev/null || true
				fi
			done
			;;
		opensuse*|suse|sled|sles)
			echo "Disabling openSUSE/SUSE firewall services..."
			# Modern openSUSE uses firewalld
			for service in firewalld SuSEfirewall2; do
				if systemctl is-active --quiet "$service" 2>/dev/null || \
				systemctl is-enabled --quiet "$service" 2>/dev/null; then
					echo " -> Stopping and disabling $service..."
					systemctl stop "$service" 2>/dev/null || true
					systemctl disable "$service" 2>/dev/null || true
					systemctl mask "$service" 2>/dev/null || true
				fi
			done
			;;
		fedora|rhel|centos|rocky|almalinux|ol)
			echo "Disabling RHEL/CentOS/Fedora firewall services..."
			# firewalld is default; iptables-services on older systems
			for service in firewalld iptables-services; do
				if systemctl is-active --quiet "$service" 2>/dev/null || \
				systemctl is-enabled --quiet "$service" 2>/dev/null; then
					echo " -> Stopping and disabling $service..."
					systemctl stop "$service" 2>/dev/null || true
					systemctl disable "$service" 2>/dev/null || true
					systemctl mask "$service" 2>/dev/null || true
				fi
			done
			;;
		*)
			echo "Unknown OS: $OS_TYPE - attempting to disable common iptables persistence services..."
			# Try to disable common services as a fallback
			for service in netfilter-persistent iptables-persistent firewalld; do
				systemctl stop "$service" 2>/dev/null || true
				systemctl disable "$service" 2>/dev/null || true
				systemctl mask "$service" 2>/dev/null || true
			done
			;;
	esac
}

# Only write config if it doesn't exist (preserve existing credentials)
if [ ! -f /etc/runic-agent/config.json ]; then
	echo "Creating initial config..."
	if [ -n "$REGISTRATION_TOKEN" ]; then
	cat > /etc/runic-agent/config.json << EOF
{
	"control_plane_url": "${CONTROL_PLANE_URL}",
	"registration_token": "${REGISTRATION_TOKEN}",
	"pull_interval_seconds": 86400,
	"log_path": "/var/log/runic/firewall.log",
	"apply_on_boot": false,
	"apply_rules_bundle": false,
	"disable_system_managed_iptables": false
}
EOF
	else
	cat > /etc/runic-agent/config.json << EOF
{
	"control_plane_url": "${CONTROL_PLANE_URL}",
	"pull_interval_seconds": 86400,
	"log_path": "/var/log/runic/firewall.log",
	"apply_on_boot": false,
	"apply_rules_bundle": false,
	"disable_system_managed_iptables": false
}
EOF
	fi
	chmod 600 /etc/runic-agent/config.json
else
	echo "Preserving existing config (credentials retained)"
	# Migrate: Add missing config options for existing installs
	MIGRATED=0
	# Migrate: Update pull_interval_seconds to 86400 for existing installs
	if ! grep -q '"pull_interval_seconds"' /etc/runic-agent/config.json 2>/dev/null; then
		echo "Adding pull_interval_seconds=86400 to existing config"
		sed -i 's/}$/,\n\t"pull_interval_seconds": 86400\n}/' /etc/runic-agent/config.json
		MIGRATED=1
	else
		# Key exists - check if value needs updating (not already 86400)
		CURRENT_INTERVAL=$(grep '"pull_interval_seconds"' /etc/runic-agent/config.json | grep -o '[0-9]\+')
		if [ -n "$CURRENT_INTERVAL" ] && [ "$CURRENT_INTERVAL" -lt 86400 ]; then
			echo "Updating pull_interval_seconds from ${CURRENT_INTERVAL} to 86400"
			sed -i 's/"pull_interval_seconds": [0-9]*/"pull_interval_seconds": 86400/' /etc/runic-agent/config.json
		fi
	fi
	if ! grep -q '"apply_on_boot"' /etc/runic-agent/config.json 2>/dev/null; then
		echo "Adding apply_on_boot=false to existing config"
		sed -i 's/}$/,\n\t"apply_on_boot": false\n}/' /etc/runic-agent/config.json
		MIGRATED=1
	fi
	if ! grep -q '"apply_rules_bundle"' /etc/runic-agent/config.json 2>/dev/null; then
		echo "Adding apply_rules_bundle=false to existing config"
		# Check if we already added a field (need comma handling)
		if [ "$MIGRATED" -eq 1 ]; then
			sed -i 's/"apply_on_boot": false\n}/"apply_on_boot": false,\n\t"apply_rules_bundle": false\n}/' /etc/runic-agent/config.json
		else
			sed -i 's/}$/,\n\t"apply_rules_bundle": false\n}/' /etc/runic-agent/config.json
		fi
		MIGRATED=1
	fi
	# AG-004: Migrate disable_system_managed_iptables if not present
	if ! grep -q '"disable_system_managed_iptables"' /etc/runic-agent/config.json 2>/dev/null; then
		echo "Adding disable_system_managed_iptables=false to existing config"
		# Check if we already added a field (need comma handling)
		if [ "$MIGRATED" -eq 1 ]; then
			sed -i 's/"apply_rules_bundle": false\n}/"apply_rules_bundle": false,\n\t"disable_system_managed_iptables": false\n}/' /etc/runic-agent/config.json
		else
			sed -i 's/}$/,\n\t"disable_system_managed_iptables": false\n}/' /etc/runic-agent/config.json
		fi
	fi
fi

# AG-005: Check config and conditionally disable iptables services
if grep '"disable_system_managed_iptables"' /etc/runic-agent/config.json 2>/dev/null | grep -q 'true'; then
	echo "Config: disable_system_managed_iptables=true - disabling system iptables services..."
	disable_iptables_services
else
	echo "Config: disable_system_managed_iptables=false - skipping system iptables services disable"
	echo "(Runic will manage iptables without disabling system services)"
fi

# Download service file
curl -fsSL -o /etc/systemd/system/runic-agent.service \
"${CONTROL_PLANE_URL}/downloads/runic-agent.service"

systemctl daemon-reload
systemctl enable runic-agent

# Use restart to handle both new installs and upgrades
systemctl restart runic-agent

echo "Runic agent installed and started."
echo "Check status: systemctl status runic-agent"
echo "View logs: journalctl -u runic-agent -f"
