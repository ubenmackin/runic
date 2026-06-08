package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	ic "runic/internal/common"
	"runic/internal/common/constants"
	"runic/internal/db"
	"runic/internal/importer"
	"runic/internal/models"
)

type DashboardStore struct {
	db       db.Querier
	logsDB   db.Querier
	settings *SettingsStore
}

func NewDashboardStore(database db.Querier, logsDB db.Querier) *DashboardStore {
	return &DashboardStore{
		db:       database,
		logsDB:   logsDB,
		settings: NewSettingsStore(database, nil),
	}
}

// GetSecret retrieves a secret value from the system_config table by key.
// Returns ("", sql.ErrNoRows) if the key does not exist.
// Delegates to SettingsStore.GetSystemConfig to avoid duplicating the SELECT query.
func (s *DashboardStore) GetSecret(ctx context.Context, key string) (string, error) {
	value, err := s.settings.GetSystemConfig(ctx, key)
	if err != nil {
		return "", fmt.Errorf("get secret %q: %w", key, err)
	}
	return value, nil
}

// FirewallLogEntry represents a single firewall log event to be inserted.
type FirewallLogEntry struct {
	PeerID       string
	PeerHostname string
	Timestamp    string
	Direction    string
	SrcIP        string
	DstIP        string
	Protocol     string
	SrcPort      int
	DstPort      int
	Action       string
	RawLine      string
}

// InsertFirewallLog inserts a single firewall log entry into the logs database.
func (s *DashboardStore) InsertFirewallLog(ctx context.Context, entry *FirewallLogEntry) error {
	if s.logsDB == nil {
		return fmt.Errorf("logs database not configured")
	}
	_, err := s.logsDB.ExecContext(ctx,
		`INSERT INTO firewall_logs (peer_id, peer_hostname, timestamp, event_type, source_ip, dest_ip, protocol, source_port, dest_port, action, details)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.PeerID, entry.PeerHostname, entry.Timestamp, entry.Direction,
		entry.SrcIP, entry.DstIP, entry.Protocol, entry.SrcPort, entry.DstPort,
		entry.Action, entry.RawLine)
	if err != nil {
		return fmt.Errorf("insert firewall log: %w", err)
	}
	return nil
}

// ParseBackupSession parses an import session's raw backup data. It requires
// a db.DB (Querier + Beginner) to start its own transaction for the parse
// operation. If the underlying database does not implement Beginner (e.g., a
// wrapped or mocked Querier), this method returns a descriptive error.
func (s *DashboardStore) ParseBackupSession(ctx context.Context, sessionID int64) error {
	database, ok := s.db.(db.DB)
	if !ok {
		return fmt.Errorf("parse backup session: underlying DB does not support transactions (type assertion failed; got %T)", s.db)
	}
	return importer.ParseSession(ctx, database, sessionID)
}

// GenerateRegistrationToken creates a new registration token and stores it in the database.
func (s *DashboardStore) GenerateRegistrationToken(ctx context.Context, token, description string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO registration_tokens (token, description) VALUES (?, ?)",
		token, description)
	if err != nil {
		return fmt.Errorf("generate registration token: %w", err)
	}
	return nil
}

// RegistrationTokenView represents a registration token for display purposes.
type RegistrationTokenView struct {
	ID             int    `json:"id"`
	Token          string `json:"token"`
	Description    string `json:"description"`
	CreatedAt      string `json:"created_at"`
	UsedAt         string `json:"used_at"`
	UsedByHostname string `json:"used_by_hostname"`
	Status         string `json:"status"`
	IsRevoked      int    `json:"is_revoked"`
}

// ListRegistrationTokens returns all registration tokens ordered by creation date descending.
func (s *DashboardStore) ListRegistrationTokens(ctx context.Context) ([]RegistrationTokenView, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, token, description, created_at, used_at, used_by_hostname, is_revoked FROM registration_tokens ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("list registration tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tokens []RegistrationTokenView
	for rows.Next() {
		var t RegistrationTokenView
		var createdAt, usedAt, usedByHostname sql.NullString

		if err := rows.Scan(&t.ID, &t.Token, &t.Description, &createdAt, &usedAt, &usedByHostname, &t.IsRevoked); err != nil {
			return nil, fmt.Errorf("scan registration token: %w", err)
		}

		t.Status = "active"
		if t.IsRevoked == 1 {
			t.Status = "revoked"
		} else if usedAt.Valid {
			t.Status = "used"
		}

		t.CreatedAt = ic.FormatSQLiteDatetime(createdAt.String)
		t.UsedAt = ic.FormatSQLiteDatetime(usedAt.String)
		t.UsedByHostname = usedByHostname.String

		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error registration tokens: %w", err)
	}
	return ic.EnsureSlice(tokens), nil
}

// RevokeRegistrationToken revokes an unused, unrevoked registration token by ID.
// Returns false if the token was not found or already used/revoked.
func (s *DashboardStore) RevokeRegistrationToken(ctx context.Context, id string) (bool, error) {
	result, err := s.db.ExecContext(ctx,
		"UPDATE registration_tokens SET is_revoked = 1 WHERE id = ? AND used_at IS NULL AND is_revoked = 0", id)
	if err != nil {
		return false, fmt.Errorf("revoke registration token: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return rowsAffected > 0, nil
}

// ConsumeRegistrationToken atomically consumes a registration token.
// Returns (true, nil) if the token was successfully consumed,
// (false, nil) if the token was already used/revoked/not found,
// (false, err) on database error.
func (s *DashboardStore) ConsumeRegistrationToken(ctx context.Context, token, hostname string) (bool, error) {
	result, err := s.db.ExecContext(ctx,
		"UPDATE registration_tokens SET used_at = CURRENT_TIMESTAMP, used_by_hostname = ? WHERE token = ? AND used_at IS NULL AND is_revoked = 0",
		hostname, token)
	if err != nil {
		return false, fmt.Errorf("consume registration token: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("getting rows affected: %w", err)
	}
	return rowsAffected > 0, nil
}

func (s *DashboardStore) GetPeerAndPolicyCounts(ctx context.Context) (totalPeers, manualPeers, onlinePeers, totalPolicies int, err error) {
	// Compute the online threshold timestamp in Go and pass as a parameter
	// to avoid string-interpolating the threshold value into the SQL query.
	onlineCutoff := time.Now().UTC().Add(-constants.OfflineThreshold).Format("2006-01-02 15:04:05")
	query := `
SELECT
	(SELECT COUNT(*) FROM peers) as total_peers,
	(SELECT COUNT(*) FROM peers WHERE is_manual = 1) as manual_peers,
(SELECT COUNT(*) FROM peers WHERE is_manual = 0 AND last_heartbeat > ?) as online_peers,
		(SELECT COUNT(*) FROM policies WHERE enabled = 1) as total_policies`

	err = s.db.QueryRowContext(ctx, query, onlineCutoff).Scan(&totalPeers, &manualPeers, &onlinePeers, &totalPolicies)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("query peer and policy counts: %w", err)
	}
	return totalPeers, manualPeers, onlinePeers, totalPolicies, nil
}

func (s *DashboardStore) GetBlockedCounts(ctx context.Context) (blockedLastHour, blockedLast24h int, err error) {
	query := `
		SELECT
		COALESCE(SUM(CASE WHEN timestamp > datetime('now', '-1 hour') THEN 1 ELSE 0 END), 0) as blocked_last_hour,
		COUNT(*) as blocked_last_24h
		FROM firewall_logs
		WHERE action = 'DROP' AND timestamp > datetime('now', '-24 hours')`

	err = s.logsDB.QueryRowContext(ctx, query).Scan(&blockedLastHour, &blockedLast24h)
	if err != nil {
		return 0, 0, fmt.Errorf("query blocked counts: %w", err)
	}
	return blockedLastHour, blockedLast24h, nil
}

func (s *DashboardStore) GetRecentActivity(ctx context.Context, limit int) ([]models.ActivityItem, error) {
	query := `
		SELECT timestamp, source_ip, dest_ip, protocol, action, peer_hostname
		FROM firewall_logs
		WHERE action = 'DROP'
		ORDER BY timestamp DESC
		LIMIT ?`

	rows, err := s.logsDB.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query recent activity: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var activities []models.ActivityItem
	for rows.Next() {
		var item models.ActivityItem
		var hostname sql.NullString
		if err := rows.Scan(&item.Timestamp, &item.SrcIP, &item.DstIP, &item.Protocol, &item.Action, &hostname); err != nil {
			return nil, fmt.Errorf("scan recent activity: %w", err)
		}
		item.Timestamp = ic.FormatSQLiteDatetime(item.Timestamp)
		if hostname.Valid {
			item.Hostname = hostname.String
		}
		activities = append(activities, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error recent activity: %w", err)
	}
	return ic.EnsureSlice(activities), nil
}

func (s *DashboardStore) GetPeerHealth(ctx context.Context) ([]models.PeerHealth, error) {
	query := `
		SELECT hostname, ip_address, agent_version, last_heartbeat, is_manual
		FROM peers
		ORDER BY hostname`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query peer health: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var healthList []models.PeerHealth
	for rows.Next() {
		var ph models.PeerHealth
		var lastHeartbeat sql.NullString
		var agentVersion sql.NullString
		var isManual bool
		if err := rows.Scan(&ph.Hostname, &ph.IP, &agentVersion, &lastHeartbeat, &isManual); err != nil {
			return nil, fmt.Errorf("scan peer health: %w", err)
		}
		if agentVersion.Valid {
			ph.AgentVersion = agentVersion.String
		}
		if lastHeartbeat.Valid {
			formatted := ic.FormatSQLiteDatetime(lastHeartbeat.String)
			ph.LastHeartbeat = formatted
			if t, err := time.Parse(time.RFC3339, formatted); err == nil {
				ph.IsOnline = time.Since(t).Seconds() < constants.OfflineThreshold.Seconds()
			}
		}
		ph.IsManual = isManual
		healthList = append(healthList, ph)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error peer health: %w", err)
	}
	return ic.EnsureSlice(healthList), nil
}

func (s *DashboardStore) GetTopBlockedSources(ctx context.Context, limit int) ([]models.BlockedIP, error) {
	query := `
		SELECT source_ip, COUNT(*) as count
		FROM firewall_logs
		WHERE action = 'DROP' AND timestamp > datetime('now', '-24 hours')
		GROUP BY source_ip
		ORDER BY count DESC
		LIMIT ?`

	rows, err := s.logsDB.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query top blocked sources: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var topSources []models.BlockedIP
	for rows.Next() {
		var b models.BlockedIP
		if err := rows.Scan(&b.SrcIP, &b.Count); err != nil {
			return nil, fmt.Errorf("scan top blocked sources: %w", err)
		}
		topSources = append(topSources, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error top blocked sources: %w", err)
	}
	return ic.EnsureSlice(topSources), nil
}
