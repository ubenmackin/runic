# Runic Firewall Management System

Manage `iptables` across multiple machines (VMs, Pis, Bare Metal, etc).

Runic lets you define firewall rules in one place, compiles them into host-specific bundles, and pushes them out via a small Go agent. If something goes wrong, a watchdog rolls the rules back so you don’t lock yourself out.

## What it does

- Central place to manage firewall rules
- Compiles policies into `iptables-restore` bundles per host
- Agent pulls and applies rules
- 90-second rollback if the agent loses contact
- Handles Docker (`DOCKER-USER` chain) correctly
- Streams firewall logs to the UI
- Default policy is DROP unless you allow it

## Quick start

### Run the server

One-liner installation (supports Ubuntu/Debian and openSUSE):

```bash
curl -sL https://raw.githubusercontent.com/ubenmackin/runic/main/scripts/install-server.sh | sudo bash
```

For custom options:
```bash
# Non-interactive with defaults
curl -sL https://raw.githubusercontent.com/ubenmackin/runic/main/scripts/install-server.sh | sudo bash -s -- --non-interactive

# With custom control plane URL
curl -sL https://raw.githubusercontent.com/ubenmackin/runic/main/scripts/install-server.sh | sudo bash -s -- --control-plane 192.168.1.100:60443
```

Server runs on `https://localhost:60443` by default.

### Install the agent

Run on each host:

```bash
curl -sL https://raw.githubusercontent.com/ubenmackin/runic/main/scripts/install-agent.sh | sudo bash -s -- https://your-runic-server:60443
```

## How it works (short version)

You define a policy → Runic expands it into raw `iptables` rules → signs the bundle → agent pulls it → verifies → applies it.

If the agent stops talking to the server, the watchdog restores the previous rules.

## Config

Server is configured with env vars. Agents use a small JSON file.

Required (server):
- `RUNIC_JWT_SECRET` - Secret key for JWT authentication (required in production)
- `RUNIC_AGENT_JWT_SECRET` - Secret key for agent JWT authentication (required in production)
- `RUNIC_HMAC_KEY` - HMAC key for signing rule bundles (required in production, has default in development)

## Troubleshooting

**Agent not connecting**
```bash
journalctl -u runic-agent -f
```

Check `control_plane_url` in `/etc/runic-agent/config.json`.

**Rules not applying**
Trigger a compile manually:
```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://runic-server-host:60443/api/v1/servers/<id>/compile
```

**SQLite locked**
Stop the server, remove any `runic.db-*` lock files, start again.

## Contributing

PRs are fine for small stuff. For bigger changes (new backends, major features), open an issue first.

## License

MIT
