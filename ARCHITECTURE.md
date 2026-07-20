# Runic Architecture

## Project Summary

Runic is a self-hosted firewall policy management system for heterogeneous homelabs. It abstracts raw iptables rules into a human-readable policy model (Groups → Services → Servers), compiles those policies into host-specific `iptables-restore` rule bundles, delivers them via a lightweight Go agent running on every managed host, and provides a unified web UI for rule management, host health visibility, and real-time log monitoring.

The name is drawn from *Runic*, Celes Chere's ability in Final Fantasy VI — she raises her blade and absorbs everything that passes through the field, deciding what gets through. That is exactly what this system does.

---

## Design Principles

1. **Abstraction over syntax** — Users manage intent (who can reach what, on which port). The system generates iptables syntax. Users never write a rule manually.
2. **Atomic delivery** — Rule bundles are applied via `iptables-restore` in a single operation per host. Partial application is not possible.
3. **Safety-first** — Every rule apply includes a 90-second auto-revert watchdog. A bad push cannot permanently lock out a host.
4. **Default deny** — Every host operates on a whitelist model. If no policy permits traffic, it is dropped. The engine always emits a final `DROP` on INPUT and OUTPUT chains.
5. **Single binary deployment** — The control plane is one Go binary that serves both the REST API and the embedded React frontend. The agent is one Go binary per arch.
6. **No forced cloud** — Runic runs entirely on-premises. No telemetry, no license checks, no external dependencies at runtime.
7. **Auditable** — Every policy change is recorded with a timestamp and description. Every bundle pushed to a host is versioned. Log events are stored locally and queryable.

---

## Technology Stack

| Layer | Technology | Rationale |
|---|---|---|
| Control plane API | Go (stdlib + Gorilla Mux router) | Single binary, fast, cross-compile trivially |
| Database | SQLite (mattn/go-sqlite3) | Zero ops, single file, sufficient for homelab scale |
| Frontend | React 18 + Vite + Tailwind CSS | Fast to build, WebSocket-friendly, excellent DX |
| Frontend state | Zustand | Lightweight, no boilerplate |
| Frontend routing | React Router v6 | Standard SPA routing |
| Real-time | WebSocket (gorilla/websocket) | Log streaming to browser; SSE for agent notifications |
| Agent | Go (stdlib + shared internal packages) | Single binary, no runtime deps, cross-compile to arm64 |
| Auth | JWT (golang-jwt/jwt) + bcrypt passwords | Simple, stateless, no SSO required |
| Rule delivery | HTTPS pull + SSE push notification | Agent polls; control plane pings on change |
| Prometheus metrics | prometheus/client_golang | Request latency, error rates, agent health stats |

---

## System Architecture

### Two-Component Topology

```
┌─────────────────────────────────────────────────────────┐
│                    Control Plane (runic-server)          │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │ REST API │  │  Engine  │  │  Embedded React SPA   │  │
│  │ (Mux)    │  │ Compiler │  │  (web/dist)           │  │
│  ├──────────┤  ├──────────┤  ├──────────────────────┤  │
│  │  Stores  │  │ Resolver │  │  WebSocket Log Hub   │  │
│  ├──────────┤  ├──────────┤  ├──────────────────────┤  │
│  │  Alerts  │  │  Signer  │  │  SSE Event Hub       │  │
│  └──────────┘  └──────────┘  └──────────────────────┘  │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │  SQLite DB (runic.db) + Logs DB (logs.db)        │   │
│  └──────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTPS (port 60443)
                       │
┌──────────────────────▼──────────────────────────────────┐
│              Agent (runic-agent) daemon                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │ Identity │  │  Puller  │  │   Rotation Manager   │  │
│  │ (Config) │  │  (HTTP)  │  │   (HMAC key rotate)  │  │
│  ├──────────┤  ├──────────┤  ├──────────────────────┤  │
│  │  Shipper │  │  Applier │  │   SSE Listener       │  │
│  │ (Logs)   │  │(iptables)│  │   (bundle updates)   │  │
│  └──────────┘  └──────────┘  └──────────────────────┘  │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Config file: /etc/runic-agent/config.json       │   │
│  │  Cache: /var/cache/runic-agent/                  │   │
│  │  iptables backup: /var/backups/runic-agent/      │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Control Plane (runic-server)

The control plane is a single Go binary that serves:
- **REST API** under `/api/v1/` — authenticated via JWT (user tokens for web UI, agent tokens for agent communication)
- **Embedded React SPA** — built with Vite, served as a Go embed (`internal/api/embed.go` → `web/dist`)
- **WebSocket endpoints** for real-time log streaming
- **SSE endpoints** for agent bundle update notifications
- **Prometheus metrics** at `/metrics`

#### Main Entrypoint (`cmd/runic-server/main.go`)

The server bootstrap follows this sequence:
1. Parse flags and environment variables (TLS cert/key, port, DB paths)
2. Validate TLS certificates
3. Initialize the main database (`runic.db`) and logs database (`logs.db`)
4. Instantiate store layer, engine compiler, alert service, encryptor
5. Create the Gorilla Mux router and register all API routes
6. Start background goroutines (change worker, push worker, log cleanup, offline detector, token cleanup)
7. Start the HTTPS listener with modern TLS config (TLS 1.2+, AEAD cipher suites, P-256/X25519 curves)
8. Wait for shutdown signal, then run graceful shutdown sequence

#### API Layer (`internal/api/`)

The API is organized by domain, split into handler packages:
- `api.go` — Central API struct, NewAPI factory, route registration, middleware setup
- `middleware.go` — Panic recovery, request ID, security headers, CORS, CSP, request logging
- `spa.go` — SPA file serving with CSP nonce injection into HTML
- `agents/` — Agent registration, bundle serving, heartbeat, log ingestion, rotation
- `auth/` — Setup wizard, login/logout, token refresh, rate limiting
- `peers/` — Peer CRUD, agent update triggers, key rotation
- `groups/` — Group CRUD, member management
- `services/` — Service CRUD (port/protocol definitions)
- `policies/` — Policy CRUD (the core abstraction: Group→Service→Server)
- `policies/` → also: policy preview compilation
- `pending/` — Pending changes, bundle previews, apply/rollback/push workflows
- `dashboard/` — Dashboard statistics, peer health, blocked IPs
- `logs/` — Firewall log queries and WebSocket streaming
- `settings/` — Log retention settings, instance configuration
- `alerts/` — Alert rules, history, SMTP config, notification preferences
- `imports/` — iptables backup import workflow
- `keys/` — Setup keys management (SMTP passwords, etc.)
- `events/` — SSE hub for agent push notifications
- `downloads/` — Agent binary download endpoint
- `common/` — Shared helpers: response encoding, error handling, change/push workers, validation
- `middleware/` — Reusable Gorilla Mux middlewares (rate limiting, RBAC)

#### Middleware Stack

The middleware chain is layered as follows (outermost first):
1. **PanicRecovery** — Catches panics, logs stack traces, returns 500
2. **SecurityHeaders** — HSTS, X-Content-Type-Options, X-Frame-Options, Permissions-Policy, etc.
3. **RequestID** — Generates/injects X-Request-ID into context and response
4. **RequestLogger** — Logs request start and completion with duration
5. **Auth middleware** — JWT validation from cookie or Bearer header (applied to protected subroutes)
6. **RBAC middleware** — Role-based access: admin, editor, viewer (applied per subrouter)
7. **CORS** — Applied to `/api/v1` subrouter; configurable origin via `CORS_ORIGIN` env var
8. **CSP** — Per-request nonce-based Content-Security-Policy (SPA routes)
9. **Rate limiters** — Per-endpoint: login (5/min), register/refresh/logout/downloads (10/min)

#### Authentication Model

Two separate auth systems:
1. **User auth (browser)** — Username + bcrypt password. Returns short-lived JWT (8h) + refresh token (7d). Used for all `/api/v1/` routes except login and setup. Refresh tokens use cookie-based rotation.
2. **Agent auth** — Agent registers and receives a long-lived JWT scoped to its `host_id`. Used for all `/api/v1/agent/` routes. Tokens stored in agent's config file with 0600 permissions.

JWT signing keys support rotation: the current key and previous key are both accepted during the rotation window, and both are persisted to the database.

Rate limiting at the login layer includes account lockout (per-username + per-IP tracking of failed attempts).

### Engine (`internal/engine/`)

The engine is the policy compiler that transforms abstract policy definitions into concrete iptables rules.

#### Compiler (`compiler.go`)

The `Compiler` struct is the central orchestrator. It:
- Loads a peer's data (hostname, IP, Docker capability, IPSet capability)
- Queries all enabled policies applicable to that peer
- Resolves entity references (groups → member IPs, special targets → addresses)
- Pre-loads service definitions (port/protocol mappings)
- Resolves IPSet definitions for group-based rule optimization
- Generates the complete `iptables-restore` payload

The output is an `iptables-restore` formatted string with sections:
1. Header (version, hostname, timestamp, policy comments)
2. IPSet definitions (if applicable)
3. Filter table header (`*filter`)
4. Policy rules (INPUT/OUTPUT pairs per policy with conntrack state matching)
5. Docker DOCKER-USER chain rules (if host has Docker)
6. Standard rules (loopback, ICMP, established/related)
7. Logging rules (`[RUNIC-DROP]` prefix) and final DROP

#### Resolver (`resolver.go`)

The `Resolver` handles entity resolution:
- Resolves groups to member IP addresses (with transitive group membership)
- Resolves special targets (subnet broadcast, limited broadcast, IGMP, mDNS, any IP, all peers)
- Handles CIDR expansion
- Validates port specifications and expands port ranges into iptables-compatible clauses
- IPSet name sanitization

#### Signer (`signer.go`)

Provides HMAC-SHA256 signing and verification for rule bundles:
- `Version(content)` — SHA-256 hash of rules content for ETag/versioning
- `Sign(content, key)` — HMAC-SHA256 signature of rules content
- `Verify(content, key, signature, version)` — HMAC verification with version-key derivation
- `DeriveHMACKey(rawKey, purpose, versionNumber)` — Key derivation for bundle signing

### Agent (`internal/agent/`)

The agent runs as a systemd service on every managed host.

#### Core Agent (`core/agent.go`)

The `Agent` struct manages the daemon lifecycle:
1. Load config from `/etc/runic-agent/config.json`
2. Register with the control plane (if not yet registered)
3. Take initial iptables backup
4. Apply boot bundle (if configured)
5. Disable system-managed iptables services (if configured)
6. Start concurrent loops:
   - **Heartbeat loop** — Sends periodic heartbeats with host metrics (uptime, load, bundle version)
   - **Poll loop** — Periodically pulls latest rule bundle from control plane
   - **SSE listener** — Long-lived SSE connection for real-time bundle update notifications
   - **Rotation check loop** — Periodically checks for pending HMAC key rotation

#### Identity (`identity/`)

- `config.go` — Config struct with JSON serialization, load/save with 0600 permissions
- `register.go` — Agent registration: sends hostname, IP, OS type, arch, kernel version, Docker detection
- `os_detect.go` — OS detection via `/etc/os-release`, with normalization (e.g., Armbian → Debian)

#### Apply (`apply/`)

The applier handles rule bundle application with safety guarantees:
- `applier.go` — Bundle application: validate rules, verify HMAC, apply via `iptables-restore`, run smoke test, schedule 90-second auto-revert watchdog
- `validate.go` — Rules content validation (nft format detection, basic structural checks)
- `restore.go` — `iptables-restore` execution via temp file
- `revert.go` — Auto-revert: schedule a delayed revert, save/load persistent backups
- `docker.go` — Docker detection and Docker restart after rule changes
- `ipset.go` — IPSet creation, population, and cleanup

#### Transport (`transport/`)

- `puller.go` — HTTP client for pulling bundles, confirming apply, listening for SSE events
- `shipper.go` — Log shipper: tails `/var/log/runic/firewall.log`, parses kernel log lines, batches and ships to control plane
- `backup.go` — Sends iptables backup to control plane for import workflow

#### Rotation (`rotation/`)

HMAC key rotation manager with state machine: `idle → rotating → testing → confirmed → failed/fallback`

### Database Layer

Two SQLite databases:
1. **Main DB** (`runic.db`) — Users, peers, groups, services, policies, rule bundles, push jobs, alert rules/history, import sessions, system configuration
2. **Logs DB** (`logs.db`) — Firewall log events (separated for performance, avoids lock contention on the main DB)

#### `internal/db/` — Low-level database primitives
- `db.go` — `InitDB`, `InitLogsDB`, `Database` wrapper struct, `RunInTx` helper
- `schema.sql` — Complete DDL with tables, indexes, constraints, and seed data
- `migrations.go` — Schema migration (add missing columns, create tables)
- `interfaces.go` — `Querier`, `Beginner`, `DB` interfaces for testability

#### `internal/store/` — Domain-specific store layer
Each domain has a dedicated store that wraps SQL queries and provides typed methods:
- `peer_store.go` — Peer CRUD, bundle management, heartbeat updates, key rotation tokens, peer IPs
- `group_store.go` — Group CRUD, member management, snapshots for rollback
- `policy_store.go` — Policy CRUD, pending change tracking, special target listing
- `service_store.go` — Service CRUD, port validation
- `user_store.go` — User CRUD, credential retrieval, pagination
- `settings_store.go` — System configuration key-value store
- `token_store.go` — Token revocation tracking
- `alert_store.go` — Alert rules, alert history, SMTP configuration, notification preferences
- `dashboard_store.go` — Dashboard statistics, firewall log insertion, registration tokens
- `import_store.go` — Import session management, rule staging, apply workflow
- `key_store.go` — Encrypted secret storage (SMTP passwords)
- `pending_store.go` — Pending changes, bundle previews, snapshots, push jobs
- `logs_store.go` — Log querying with filtering and pagination

Store methods that modify data follow a snapshot-then-modify pattern for rollback support. The `transaction.go` file provides generic helpers for common SQL patterns.

### Data Model

#### Core Abstraction

```
GROUP (source IPs) → SERVICE (ports/protocol) → SERVER (destination host)
```

A **Policy** says: "Members of group X may access service Y on server Z."

#### Entity Types

| Entity | Description |
|---|---|
| **Peer** | A managed host (agent or manual peer) with IP address, OS info, bundle version, heartbeat status |
| **Group** | A named set of peers (source IPs for policies) |
| **Service** | A named port/protocol definition (e.g., "SSH" = tcp/22) |
| **Policy** | The access rule connecting Group→Service→Server with action (ACCEPT/DROP/LOG_DROP), direction, priority, and target scope |
| **Rule Bundle** | A compiled `iptables-restore` payload for a specific peer, versioned and HMAC-signed |
| **Special Target** | Pre-defined targets (any IP, all peers, subnet broadcast, limited broadcast, multicast addresses) |

#### Policy Configuration

Policies support:
- **Source types**: Group, Peer, Any
- **Target types**: Peer, Any, Special (broadcast, multicast, etc.)
- **Actions**: ACCEPT, DROP, LOG_DROP
- **Direction**: forward (source→target), backward (target→source), both
- **Target scope**: host, docker, both (controls which chains are written)
- **Priority ordering**: Lower number = higher priority
- **IP override**: source_ip and target_ip fields for explicit addressing
- **Services with custom ports, protocols (tcp/udp/sctp), port ranges, source ports**
- **NoConntrack flag** for protocols like IGMP and VRRP

#### Rule Output Format

Each policy generates paired iptables rules:
- `-A INPUT -s <source_cidr> -p <proto> --dport <port> -m state --state NEW,ESTABLISHED -j ACCEPT`
- `-A OUTPUT -d <source_cidr> -p <proto> --sport <port> -m state --state ESTABLISHED -j ACCEPT`

With standard prologue (loopback, ICMP, established/related) and epilogue (logging, DROP).

### Alert System (`internal/alerts/`)

The alert system monitors firewall events and peer status:
- **Rule types**: peer_offline, bundle_failed, blocked_spike, peer_online, new_peer, bundle_deployed
- **Delivery**: SMTP email with configurable SMTP settings (password encrypted at rest)
- **Digest mode**: Aggregated daily/weekly digests
- **Throttling**: Per-rule throttle window to prevent alert storms
- **Notification preferences**: Per-user quiet hours, enabled alert types
- **Scheduling**: Cron-like scheduler for digest timing
- **Spike detector**: Detects unusual increases in dropped traffic using configurable thresholds

### Metrics (`internal/metrics/`)

Prometheus-based instrumentation:
- Request counts, latency histograms, error rates by endpoint
- Agent heartbeat metrics (online/offline counts)
- Prometheus HTTP handler at `/metrics`

### Common Utilities (`internal/common/`)

Shared packages:
- `log/` — Structured logging with context propagation, request IDs
- `version/` — Build version injection at compile time
- `signal/` — OS signal handling (SIGINT, SIGTERM)
- `systemd/` — Systemd service management helpers
- `constants/` — Shared constants (timeouts, intervals)
- `crypto.go` — AES-256-GCM encryption for sensitive data
- `errors.go` — Standard error types (`ErrUnauthorized`, `HTTPStatusError`)
- `http.go` — HTTP client helpers (`DoJSONRequest`)
- `datetime.go` — SQLite datetime formatting
- `ensure.go` — Path/directory creation helpers
- `system.go` — OS-level detection (firewalld, ufw, nftables)

### Importer (`internal/importer/`)

The import workflow allows users to migrate existing iptables rules into the policy model:
1. Agent sends iptables backup to control plane
2. Parser (`internal/iptparse/`) parses raw rules into structured format
3. Staging tables store parsed rules, group mappings, peer mappings, service mappings
4. Users review and map imported rules to existing or new policies/groups/services
5. Apply creates the policies and triggers bundle recompilation

### Security Architecture

1. **TLS everywhere** — All control plane communication requires TLS 1.2+ with modern AEAD cipher suites and P-256/X25519 curves
2. **JWT with rotation** — Signing keys support rotation; previous key accepted during rotation window
3. **CSP with nonces** — Per-request nonces prevent inline script injection; strict CSP for API routes
4. **Rate limiting** — Multi-layered: per-endpoint (login, register, etc.), per-IP (setup), account lockout (failed attempts)
5. **Token revocation** — Access and refresh tokens can be revoked; expired tokens cleaned up periodically
6. **RBAC** — Three roles: admin (full access), editor (CRUD operations), viewer (read-only)
7. **HMAC bundle signing** — Rule bundles are HMAC-SHA256 signed; agent verifies before applying
8. **Safe apply** — 90-second auto-revert watchdog prevents lockout from bad rules
9. **Encrypted secrets** — SMTP passwords encrypted with AES-256-GCM, key stored in database
10. **Security headers** — HSTS, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, etc.
11. **CORS** — Explicit allowlist; no wildcard reflection in production

---

## Directory Layout

```
cmd/runic-server/        — Control plane entrypoint
cmd/runic-agent/         — Agent entrypoint
internal/
  agent/                 — Agent implementation
    core/                — Agent daemon lifecycle
    identity/            — Config, registration, OS detection
    apply/               — Bundle application, validation, revert
    transport/           — HTTP puller, log shipper, SSE listener
    rotation/            — HMAC key rotation
    firewall/            — Command runner interface
    metrics/             — Heartbeat sender
  api/                   — HTTP API layer
    agents/              — Agent-facing endpoints
    alerts/              — Alert rule/history/notification endpoints
    auth/                — Authentication endpoints + rate limiting
    common/              — Shared API utilities (response, errors, workers)
    dashboard/           — Dashboard statistics endpoints
    downloads/           — Agent binary download
    events/              — SSE hub
    groups/              — Group CRUD endpoints
    imports/             — Import workflow endpoints
    keys/                — Secret management endpoints
    logs/                — Log query + WebSocket streaming
    middleware/          — Rate limiting, RBAC middlewares
    peers/               — Peer CRUD endpoints
    pending/             — Pending changes/bundle endpoints
    policies/            — Policy CRUD endpoints
    services/            — Service CRUD endpoints
    settings/            — Settings endpoints
    users/               — User management endpoints
  alerts/                — Alert rule engine, evaluator, SMTP, spike detector, scheduler, digest
  auth/                  — JWT utilities, middleware, token management
  common/                — Shared utilities (log, crypto, HTTP, errors, system, etc.)
  crypto/                — AES-256-GCM encryptor
  db/                    — Database initialization, migrations, queries
  engine/                — Policy compiler, resolver, signer
  importer/              — iptables import workflow
  integrationtest/       — Integration tests
  iptparse/              — iptables-save output parser
  logcleanup/            — Log retention worker
  metrics/               — Prometheus metrics
  models/                — Data models (PeerRow, PolicyRow, etc.)
  resolve/               — DNS resolution utility
  sqlutil/               — SQL utilities
  store/                 — Domain-specific data stores
  testutil/              — Test helpers (test DB, HTTP test utilities)
web/                     — React frontend source (built to web/dist)
scripts/                 — Installation scripts, systemd units
docs/                    — API documentation (OpenAPI spec)
AGENT_DOCS/              — Agent-facing documentation
```

---

## Update History

| Date | Entry |
|---|---|
| 2026-07-12 | Initial architecture document created from project analysis. Captures the complete two-component (server + agent) architecture, engine compiler pipeline, store layer, alert system, security model, and data model for the Runic firewall policy management system. |