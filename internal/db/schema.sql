CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS peers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT UNIQUE NOT NULL,
    ip_address TEXT NOT NULL,
    os_type TEXT NOT NULL DEFAULT 'linux',
    arch TEXT NOT NULL DEFAULT 'amd64',
    has_docker BOOLEAN NOT NULL DEFAULT 0,
    agent_key TEXT UNIQUE NOT NULL,
    agent_token TEXT,
    agent_version TEXT,
    is_manual BOOLEAN NOT NULL DEFAULT 0,
    bundle_version TEXT,
    hmac_key TEXT NOT NULL,
    last_heartbeat DATETIME,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    description TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS group_members (
id INTEGER PRIMARY KEY AUTOINCREMENT,
group_id INTEGER NOT NULL,
peer_id INTEGER NOT NULL,
added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
FOREIGN KEY(peer_id) REFERENCES peers(id) ON DELETE CASCADE,
UNIQUE(group_id, peer_id)
);
CREATE INDEX IF NOT EXISTS idx_group_members_peer_id ON group_members(peer_id);

CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  ports TEXT NOT NULL DEFAULT '',
  protocol TEXT NOT NULL DEFAULT 'tcp',
  description TEXT,
  direction_hint TEXT NOT NULL DEFAULT 'inbound',
  is_system BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS policies (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	description TEXT,
	source_group_id INTEGER NOT NULL,
	service_id INTEGER NOT NULL,
	target_peer_id INTEGER NOT NULL,
	action TEXT NOT NULL DEFAULT 'ACCEPT' CHECK(action IN ('ACCEPT', 'DROP', 'LOG_DROP')),
	priority INTEGER NOT NULL DEFAULT 100,
	enabled BOOLEAN NOT NULL DEFAULT 1,
	docker_only BOOLEAN NOT NULL DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(source_group_id) REFERENCES groups(id),
	FOREIGN KEY(service_id) REFERENCES services(id),
	FOREIGN KEY(target_peer_id) REFERENCES peers(id)
);

CREATE TABLE IF NOT EXISTS rule_bundles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id INTEGER NOT NULL,
    version TEXT NOT NULL,
    rules_content TEXT NOT NULL,
    hmac TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    applied_at DATETIME,
    FOREIGN KEY(peer_id) REFERENCES peers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    unique_id TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS firewall_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id INTEGER NOT NULL,
    timestamp DATETIME NOT NULL,
    direction TEXT,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    action TEXT NOT NULL,
    raw_line TEXT,
    FOREIGN KEY(peer_id) REFERENCES peers(id) ON DELETE CASCADE
);

-- Indexes for frequently queried columns
CREATE INDEX IF NOT EXISTS idx_peers_last_heartbeat ON peers(last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_firewall_logs_timestamp ON firewall_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_firewall_logs_peer_id ON firewall_logs(peer_id);

-- Composite indexes for common query patterns
-- Efficient for log queries filtering by peer_id AND ordering by timestamp DESC
CREATE INDEX IF NOT EXISTS idx_firewall_logs_peer_timestamp ON firewall_logs(peer_id, timestamp DESC);
-- Efficient for finding offline peers by status AND last_heartbeat
CREATE INDEX IF NOT EXISTS idx_peers_status_heartbeat ON peers(status, last_heartbeat);
