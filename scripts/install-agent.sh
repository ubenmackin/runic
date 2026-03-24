#!/bin/bash
set -e

ARCH=$(uname -m)
case $ARCH in
    x86_64)  AGENT_ARCH="amd64" ;;
    aarch64) AGENT_ARCH="arm64" ;;
    armv7l)  AGENT_ARCH="arm"   ;;
    *)       echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

CONTROL_PLANE_URL="${1:-}"
if [ -z "$CONTROL_PLANE_URL" ]; then
    echo "Usage: install-agent.sh <control-plane-url>"
    echo "Example: install-agent.sh https://runic.home.lan:8080"
    exit 1
fi

BINARY_URL="${CONTROL_PLANE_URL}/downloads/runic-agent-linux-${AGENT_ARCH}"

echo "Downloading runic-agent for ${AGENT_ARCH}..."
curl -fsSL -o /usr/local/bin/runic-agent "$BINARY_URL"
chmod +x /usr/local/bin/runic-agent

mkdir -p /etc/runic-agent
chmod 700 /etc/runic-agent

# Write minimal config to trigger registration on first start
cat > /etc/runic-agent/config.json << EOF
{
  "control_plane_url": "${CONTROL_PLANE_URL}",
  "pull_interval_seconds": 30,
  "log_path": "/var/log/firewall"
}
EOF
chmod 600 /etc/runic-agent/config.json

curl -fsSL -o /etc/systemd/system/runic-agent.service \
    "${CONTROL_PLANE_URL}/downloads/runic-agent.service"

systemctl daemon-reload
systemctl enable runic-agent
systemctl start runic-agent

echo "Runic agent installed and started."
echo "Check status: systemctl status runic-agent"
echo "View logs: journalctl -u runic-agent -f"
