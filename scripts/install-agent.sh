#!/bin/bash
set -e

ARCH=$(uname -m)
case $ARCH in
x86_64) AGENT_ARCH="amd64" ;;
aarch64) AGENT_ARCH="arm64" ;;
armv7l) AGENT_ARCH="arm" ;;
*) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

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
mkdir -p /var/log/firewall
chmod 755 /var/log/firewall

# Install rsyslog config for firewall logs
if [ -d /etc/rsyslog.d ]; then
    cat > /etc/rsyslog.d/30-runic-firewall.conf << 'EOF'
# Runic Firewall - Route firewall log messages to dedicated file
# This filters kernel messages with [RUNIC- prefix (from iptables LOG target)
if $programname == 'kernel' and $msg contains '[RUNIC-' then {
    action(type="omfile" file="/var/log/firewall/firewall.log")
    stop
}
EOF
    chmod 644 /etc/rsyslog.d/30-runic-firewall.conf
    systemctl restart rsyslog 2>/dev/null || true
fi

# Only write config if it doesn't exist (preserve existing credentials)
if [ ! -f /etc/runic-agent/config.json ]; then
echo "Creating initial config..."
cat > /etc/runic-agent/config.json << EOF
{
"control_plane_url": "${CONTROL_PLANE_URL}",
"pull_interval_seconds": 30,
"log_path": "/var/log/firewall/firewall.log"
}
EOF
chmod 600 /etc/runic-agent/config.json
else
echo "Preserving existing config (credentials retained)"
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
