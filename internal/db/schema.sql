CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT DEFAULT '',
    role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('admin', 'editor', 'viewer')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS peers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT UNIQUE NOT NULL CHECK(hostname != ''),
    ip_address TEXT NOT NULL,
    os_type TEXT NOT NULL DEFAULT 'linux',
    arch TEXT NOT NULL DEFAULT 'amd64',
    has_docker BOOLEAN NOT NULL DEFAULT 0,
    has_ipset BOOLEAN DEFAULT NULL,
    agent_key TEXT UNIQUE NOT NULL,
    agent_token TEXT,
    agent_version TEXT,
    is_manual BOOLEAN NOT NULL DEFAULT 0,
    bundle_version TEXT,
    hmac_key TEXT NOT NULL,
    hmac_key_rotation_token TEXT,
    hmac_key_last_rotated_at DATETIME,
    last_heartbeat DATETIME,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    description TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT 0,
    is_pending_delete BOOLEAN NOT NULL DEFAULT 0
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
    source_ports TEXT DEFAULT '',
    protocol TEXT NOT NULL DEFAULT 'tcp',
    description TEXT,
    direction_hint TEXT NOT NULL DEFAULT 'inbound',
    is_system BOOLEAN NOT NULL DEFAULT 0,
    no_conntrack BOOLEAN NOT NULL DEFAULT 0,
    is_pending_delete BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS policies (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	description TEXT,
	source_id INTEGER NOT NULL,
	source_type TEXT NOT NULL,
	service_id INTEGER NOT NULL,
	target_id INTEGER NOT NULL,
	target_type TEXT NOT NULL,
	action TEXT NOT NULL DEFAULT 'ACCEPT' CHECK(action IN ('ACCEPT', 'DROP', 'LOG_DROP')),
	priority INTEGER NOT NULL DEFAULT 100,
	enabled BOOLEAN NOT NULL DEFAULT 1,
	target_scope TEXT NOT NULL DEFAULT 'both' CHECK(target_scope IN ('both', 'host', 'docker')),
	direction TEXT NOT NULL DEFAULT 'both' CHECK(direction IN ('both', 'forward', 'backward')),
	is_pending_delete BOOLEAN NOT NULL DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(service_id) REFERENCES services(id)
);

CREATE TABLE IF NOT EXISTS rule_bundles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id INTEGER NOT NULL,
    version TEXT NOT NULL,
    version_number INTEGER NOT NULL DEFAULT 0,
    rules_content TEXT NOT NULL,
    hmac TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    applied_at DATETIME,
    FOREIGN KEY(peer_id) REFERENCES peers(id) ON DELETE CASCADE,
    UNIQUE(peer_id, version)
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    unique_id TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    token_type TEXT NOT NULL DEFAULT 'unknown'
);

CREATE TABLE IF NOT EXISTS firewall_logs (
id INTEGER PRIMARY KEY AUTOINCREMENT,
peer_id INTEGER NOT NULL,
peer_hostname TEXT,
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

CREATE TABLE IF NOT EXISTS special_targets (
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  description TEXT,
  address TEXT NOT NULL
);

-- Special targets for policy resolution
INSERT OR IGNORE INTO special_targets (id, name, display_name, description, address) VALUES
(1, '__subnet_broadcast__', 'Subnet Broadcast', 'The broadcast address for the peer''s subnet (e.g., 10.100.5.255)', 'computed'),
(2, '__limited_broadcast__', 'Limited Broadcast', 'The limited broadcast address (255.255.255.255)', '255.255.255.255'),
(3, '__all_hosts__', 'All Hosts (IGMP)', 'All hosts multicast address for IGMP (224.0.0.1)', '224.0.0.1'),
(4, '__mdns__', 'mDNS', 'mDNS multicast address (224.0.0.251)', '224.0.0.251'),
(5, 'loopback', 'Loopback', 'Local loopback address (127.0.0.1)', '127.0.0.1'),
(6, '__any_ip__', 'Any IP (0.0.0.0/0)', 'Any IP address on the internet (0.0.0.0/0)', '0.0.0.0/0'),
(7, '__all_peers__', 'All Peers', 'All registered peer IPs', 'dynamic'),
(8, '__igmpv3__', 'IGMPv3', 'IGMPv3 multicast address (224.0.0.22)', '224.0.0.22');

-- Indexes for frequently queried columns
CREATE INDEX IF NOT EXISTS idx_peers_last_heartbeat ON peers(last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_firewall_logs_timestamp ON firewall_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_firewall_logs_peer_id ON firewall_logs(peer_id);

-- Composite indexes for common query patterns
-- Efficient for log queries filtering by peer_id AND ordering by timestamp DESC
CREATE INDEX IF NOT EXISTS idx_firewall_logs_peer_timestamp ON firewall_logs(peer_id, timestamp DESC);
-- Efficient for finding offline peers by status AND last_heartbeat
CREATE INDEX IF NOT EXISTS idx_peers_status_heartbeat ON peers(status, last_heartbeat);
-- Efficient for dashboard queries filtering by action AND timestamp
CREATE INDEX IF NOT EXISTS idx_firewall_logs_action_timestamp ON firewall_logs(action, timestamp DESC);

CREATE TABLE IF NOT EXISTS registration_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    description TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    used_at DATETIME,
    used_by_hostname TEXT,
    is_revoked INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_reg_tokens_active ON registration_tokens(used_at, is_revoked);

-- System configuration table for storing control plane settings
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS push_jobs (
    id TEXT PRIMARY KEY,
    initiated_by TEXT,
    total_peers INTEGER NOT NULL,
    succeeded_count INTEGER DEFAULT 0,
    failed_count INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('pending', 'running', 'completed', 'completed_with_errors', 'failed', 'cancelled')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME
);

CREATE TABLE IF NOT EXISTS push_job_peers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES push_jobs(id) ON DELETE CASCADE,
    peer_id INTEGER NOT NULL REFERENCES peers(id),
    peer_hostname TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'notified', 'applied', 'failed')),
    error_message TEXT,
    notified_at DATETIME,
    applied_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(job_id, peer_id)
);
CREATE INDEX IF NOT EXISTS idx_push_job_peers_job_id ON push_job_peers(job_id);
CREATE INDEX IF NOT EXISTS idx_push_jobs_status ON push_jobs(status);

-- Pending changes tracking for peer configurations
CREATE TABLE IF NOT EXISTS pending_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id INTEGER NOT NULL,
    change_type TEXT NOT NULL,
    change_id INTEGER NOT NULL,
    change_action TEXT NOT NULL,
    change_summary TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(peer_id) REFERENCES peers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pending_changes_peer ON pending_changes(peer_id);

-- Pending bundle previews for peer configuration previews
CREATE TABLE IF NOT EXISTS pending_bundle_previews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id INTEGER NOT NULL UNIQUE,
    rules_content TEXT NOT NULL,
    diff_content TEXT,
    version_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(peer_id) REFERENCES peers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pending_bundle_previews_peer ON pending_bundle_previews(peer_id);

CREATE TABLE IF NOT EXISTS change_snapshots (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	entity_type TEXT NOT NULL CHECK (entity_type IN ('group', 'service', 'policy')),
	entity_id INTEGER NOT NULL,
	action TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete')),
	snapshot_data TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(entity_type, entity_id)
);

-- Alert system tables

-- Alert rules: stores alert rule definitions
CREATE TABLE IF NOT EXISTS alert_rules (
id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT NOT NULL,
alert_type TEXT NOT NULL CHECK(alert_type IN ('peer_offline', 'bundle_failed', 'blocked_spike', 'peer_online', 'new_peer', 'bundle_deployed')),
enabled BOOLEAN NOT NULL DEFAULT 1,
threshold_value INTEGER,
threshold_window_minutes INTEGER,
peer_id TEXT,
throttle_minutes INTEGER NOT NULL DEFAULT 5,
created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_alert_rules_type_enabled ON alert_rules(alert_type, enabled);
CREATE INDEX IF NOT EXISTS idx_alert_rules_peer_id ON alert_rules(peer_id);

-- Alert history: stores alert event history
CREATE TABLE IF NOT EXISTS alert_history (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	rule_id INTEGER REFERENCES alert_rules(id),
	alert_type TEXT NOT NULL,
	peer_id TEXT,
	severity TEXT NOT NULL CHECK(severity IN ('info', 'warning', 'critical')),
	subject TEXT NOT NULL,
	message TEXT NOT NULL,
	metadata TEXT,
	status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'sent', 'failed')),
	sent_at DATETIME,
	error_message TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_alert_history_rule_id ON alert_history(rule_id);
CREATE INDEX IF NOT EXISTS idx_alert_history_status ON alert_history(status);
CREATE INDEX IF NOT EXISTS idx_alert_history_created_at ON alert_history(created_at DESC);

-- User notification preferences: stores per-user notification settings
CREATE TABLE IF NOT EXISTS user_notification_preferences (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	enabled_alerts TEXT DEFAULT '[]',
	quiet_hours_start TEXT DEFAULT '22:00',
	quiet_hours_end TEXT DEFAULT '07:00',
	quiet_hours_timezone TEXT DEFAULT 'UTC',
	digest_enabled BOOLEAN NOT NULL DEFAULT 0,
	digest_time TEXT DEFAULT '08:00',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(user_id)
);
CREATE INDEX IF NOT EXISTS idx_user_notification_prefs_user_id ON user_notification_preferences(user_id);

-- Alert digests: stores daily digest history
CREATE TABLE IF NOT EXISTS alert_digests (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	digest_date DATE NOT NULL,
	alert_count INTEGER NOT NULL DEFAULT 0,
	summary TEXT,
	sent_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(user_id, digest_date)
);
CREATE INDEX IF NOT EXISTS idx_alert_digests_user_date ON alert_digests(user_id, digest_date DESC);
