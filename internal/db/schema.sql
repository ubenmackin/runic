CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT UNIQUE NOT NULL,
    ip_address TEXT NOT NULL,
    os_type TEXT NOT NULL DEFAULT 'linux',
    arch TEXT NOT NULL DEFAULT 'amd64',
    has_docker BOOLEAN NOT NULL DEFAULT 0,
    agent_key TEXT UNIQUE NOT NULL,
    agent_token TEXT,
    agent_version TEXT,
    bundle_version TEXT,
    hmac_key TEXT NOT NULL,
    last_heartbeat DATETIME,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS group_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    value TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('ip', 'cidr', 'group_ref')),
    FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    ports TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT 'tcp',
    description TEXT,
    direction_hint TEXT NOT NULL DEFAULT 'inbound'
);

CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    source_group_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    target_server_id INTEGER NOT NULL,
    action TEXT NOT NULL DEFAULT 'ACCEPT' CHECK(action IN ('ACCEPT', 'DROP', 'LOG_DROP')),
    priority INTEGER NOT NULL DEFAULT 100,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(source_group_id) REFERENCES groups(id),
    FOREIGN KEY(service_id) REFERENCES services(id),
    FOREIGN KEY(target_server_id) REFERENCES servers(id)
);

CREATE TABLE IF NOT EXISTS rule_bundles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    version TEXT NOT NULL,
    rules_content TEXT NOT NULL,
    hmac TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    applied_at DATETIME,
    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    unique_id TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS firewall_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    timestamp DATETIME NOT NULL,
    direction TEXT,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    action TEXT NOT NULL,
    raw_line TEXT,
    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
);

-- Indexes for frequently queried columns
CREATE INDEX IF NOT EXISTS idx_servers_last_heartbeat ON servers(last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_firewall_logs_timestamp ON firewall_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_firewall_logs_server_id ON firewall_logs(server_id);

-- Composite indexes for common query patterns
-- Efficient for log queries filtering by server_id AND ordering by timestamp DESC
CREATE INDEX IF NOT EXISTS idx_firewall_logs_server_timestamp ON firewall_logs(server_id, timestamp DESC);
-- Efficient for finding offline servers by status AND last_heartbeat
CREATE INDEX IF NOT EXISTS idx_servers_status_heartbeat ON servers(status, last_heartbeat);
