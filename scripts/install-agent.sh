#!/bin/bash
set -e

ARCH=$(uname -m)
case $ARCH in
x86_64) AGENT_ARCH="amd64" ;;
aarch64) AGENT_ARCH="arm64" ;;
armv7l) AGENT_ARCH="arm" ;;
armv6l) AGENT_ARCH="arm" ;;
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
if [ -z "$CONTROL_PLANE_URL" ]; then
echo "Usage: install-agent.sh <control-plane-url>"
echo "Example: install-agent.sh https://runic.home.lan:60443"
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
:msg,contains,"[RUNIC " /var/log/runic/firewall.log
& stop
EOF
    chmod 644 /etc/rsyslog.d/30-runic-firewall.conf
    systemctl restart rsyslog 2>/dev/null || true
fi

# Disable netfilter-persistent/iptables-persistent to prevent conflicts with runic's firewall management
# These services restore saved iptables rules on boot, which would conflict with runic's rule management
for service in netfilter-persistent iptables-persistent; do
    if systemctl is-active --quiet "$service" 2>/dev/null || \
       systemctl is-enabled --quiet "$service" 2>/dev/null; then
        echo "Disabling $service service..."
        echo "  -> Stopping and disabling to prevent conflicts with runic firewall management"
        systemctl stop "$service" 2>/dev/null || true
        systemctl disable "$service" 2>/dev/null || true
        # Mask to prevent any other package from re-enabling it
        systemctl mask "$service" 2>/dev/null || true
    fi
done

# Only write config if it doesn't exist (preserve existing credentials)
if [ ! -f /etc/runic-agent/config.json ]; then
	echo "Creating initial config..."
	cat > /etc/runic-agent/config.json << EOF
{
	"control_plane_url": "${CONTROL_PLANE_URL}",
	"pull_interval_seconds": 30,
	"log_path": "/var/log/runic/firewall.log",
	"apply_on_boot": false,
	"apply_rules_bundle": false
}
EOF
	chmod 600 /etc/runic-agent/config.json
else
	echo "Preserving existing config (credentials retained)"
	# Migrate: Add missing config options for existing installs
	MIGRATED=0
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
	fi
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
