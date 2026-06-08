package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"

	"runic/internal/api/common"
	ic "runic/internal/common"
	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/models"
)

const peerRowColumns = `id, hostname, ip_address, os_type, arch, has_docker, agent_key, agent_token, agent_version, is_manual, bundle_version, last_heartbeat, COALESCE(status, ''), created_at`

const ruleBundleRowColumns = `id, peer_id, version, version_number, rules_content, hmac, created_at, applied_at, first_applied_at`

type PeerIPView struct {
	ID        int    `json:"id"`
	PeerID    int    `json:"peer_id"`
	IPAddress string `json:"ip_address"`
	IsPrimary bool   `json:"is_primary"`
}

type PeerView struct {
	ID                   int          `json:"id"`
	Hostname             string       `json:"hostname"`
	IPAddress            string       `json:"ip_address"`
	OSType               string       `json:"os_type"`
	Arch                 string       `json:"arch"`
	HasDocker            bool         `json:"has_docker"`
	IsManual             bool         `json:"is_manual"`
	AgentVersion         string       `json:"agent_version"`
	LastHeartbeat        string       `json:"last_heartbeat"`
	Status               string       `json:"status"`
	IsOnline             bool         `json:"is_online"`
	HasPendingChanges    bool         `json:"has_pending_changes"`
	SyncStatus           string       `json:"sync_status"`
	BundleVersion        string       `json:"bundle_version"`
	PendingBundleVersion string       `json:"pending_bundle_version"`
	PendingChangesCount  int          `json:"pending_changes_count"`
	Groups               string       `json:"groups"`
	IPs                  []PeerIPView `json:"ips"`
	Description          string       `json:"description"`
	HMACKeyLastRotatedAt string       `json:"hmac_key_last_rotated_at"`
}

type PeerStore struct {
	db db.DB
}

func NewPeerStore(database db.DB) *PeerStore {
	return &PeerStore{db: database}
}

// ListPeers returns all peers. It uses a two-query approach: first fetches peers with a complex join, then
// fetches all peer IPs and joins them in Go.
func (s *PeerStore) ListPeers(ctx context.Context) ([]PeerView, error) {
	query := `
SELECT p.id, p.hostname, p.ip_address, p.os_type, p.arch, p.has_docker, p.is_manual,
COALESCE(p.agent_version, '') as agent_version,
COALESCE(p.last_heartbeat, '') as last_heartbeat,
CASE
WHEN p.last_heartbeat IS NULL THEN 'pending'
WHEN p.last_heartbeat < ` + fmt.Sprintf("datetime('now', '-%d seconds')", int(constants.OfflineThreshold.Seconds())) + ` THEN 'offline'
ELSE COALESCE(p.status, 'online')
END as status,
COALESCE(p.bundle_version, '') as bundle_version,
COALESCE((SELECT rb.version_number FROM rule_bundles rb WHERE rb.peer_id = p.id ORDER BY rb.created_at DESC LIMIT 1), 0) as bundle_version_number,
COALESCE(GROUP_CONCAT(g.name, ','), '') as groups,
COALESCE(p.description, '') as description,
COALESCE(p.hmac_key_last_rotated_at, '') as hmac_key_last_rotated_at,
(SELECT COUNT(*) FROM pending_changes pc JOIN peers p2 ON pc.peer_id = p2.id WHERE pc.peer_id = p.id AND p2.is_manual = 0) as pending_changes_count,
	CASE
		WHEN (SELECT COUNT(*) FROM pending_changes pc JOIN peers p2 ON pc.peer_id = p2.id WHERE pc.peer_id = p.id AND p2.is_manual = 0) > 0 THEN 'pending'
		WHEN (SELECT rb.version FROM rule_bundles rb WHERE rb.peer_id = p.id ORDER BY rb.created_at DESC LIMIT 1) IS NOT NULL
		AND (
			(SELECT rb.applied_at FROM rule_bundles rb WHERE rb.peer_id = p.id ORDER BY rb.created_at DESC LIMIT 1) IS NULL
			OR (SELECT rb.version FROM rule_bundles rb WHERE rb.peer_id = p.id ORDER BY rb.created_at DESC LIMIT 1) != COALESCE(p.bundle_version, '')
		) THEN 'pending_sync'
		ELSE 'synced'
	END as sync_status
FROM peers p
LEFT JOIN group_members gm ON p.id = gm.peer_id
LEFT JOIN groups g ON gm.group_id = g.id
GROUP BY p.id
ORDER BY p.hostname ASC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query peers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var peers []PeerView
	for rows.Next() {
		var p PeerView
		var agentVersion, lastHeartbeat, description, hmacKeyLastRotatedAt sql.NullString
		var groupsStr string
		var status string
		if err := rows.Scan(
			&p.ID, &p.Hostname, &p.IPAddress, &p.OSType, &p.Arch,
			&p.HasDocker, &p.IsManual, &agentVersion, &lastHeartbeat,
			&status, &p.BundleVersion, &p.PendingBundleVersion, &groupsStr,
			&description, &hmacKeyLastRotatedAt, &p.PendingChangesCount, &p.SyncStatus,
		); err != nil {
			return nil, fmt.Errorf("scan peer: %w", err)
		}
		if agentVersion.Valid {
			p.AgentVersion = agentVersion.String
		}
		if lastHeartbeat.Valid {
			p.LastHeartbeat = ic.FormatSQLiteDatetime(lastHeartbeat.String)
		}
		if description.Valid {
			p.Description = description.String
		}
		if hmacKeyLastRotatedAt.Valid {
			p.HMACKeyLastRotatedAt = ic.FormatSQLiteDatetime(hmacKeyLastRotatedAt.String)
		}

		p.Status = status
		p.IsOnline = p.Status == "online"
		p.HasPendingChanges = p.PendingChangesCount > 0 || p.SyncStatus == "pending"

		p.Groups = groupsStr

		p.IPs = []PeerIPView{}
		peers = append(peers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	ipRows, err := s.db.QueryContext(ctx, "SELECT id, peer_id, ip_address, is_primary FROM peer_ips ORDER BY peer_id, is_primary DESC")
	if err != nil {
		log.WarnContext(ctx, "failed to query peer_ips", "error", err)
		// Non-fatal: return peers without IPs
		return ic.EnsureSlice(peers), nil
	}
	defer func() { _ = ipRows.Close() }()

	// Build a map of peer_id -> []PeerIPView
	ipMap := make(map[int][]PeerIPView)
	for ipRows.Next() {
		var pip PeerIPView
		var isPrimary int
		if err := ipRows.Scan(&pip.ID, &pip.PeerID, &pip.IPAddress, &isPrimary); err != nil {
			log.WarnContext(ctx, "failed to scan peer_ip", "error", err)
			continue
		}
		pip.IsPrimary = isPrimary == 1
		ipMap[pip.PeerID] = append(ipMap[pip.PeerID], pip)
	}

	// Attach IPs to each peer
	for i := range peers {
		if ips, ok := ipMap[peers[i].ID]; ok {
			peers[i].IPs = ips
		}
	}

	return ic.EnsureSlice(peers), nil
}

func (s *PeerStore) CreatePeer(ctx context.Context, hostname, ip, osType, arch, agentKey, hmacKey string, hasDocker bool, isManual bool) (int64, error) {
	if hostname == "" {
		return 0, errors.New("hostname is required")
	}
	if ip != "" && net.ParseIP(ip) == nil {
		return 0, fmt.Errorf("invalid IP address: %q", ip)
	}
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO peers (hostname, ip_address, os_type, arch, agent_key, hmac_key, has_docker, is_manual) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		hostname, ip, osType, arch, agentKey, hmacKey, hasDocker, isManual)
	if err != nil {
		return 0, fmt.Errorf("insert peer: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get insert id: %w", err)
	}
	return id, nil
}

func (s *PeerStore) UpdatePeer(ctx context.Context, id int, hostname, ip, osType, arch string, hasDocker bool, description string) error {
	existing, err := s.GetPeerByID(ctx, id)
	if err != nil {
		return fmt.Errorf("get existing peer: %w", err)
	}

	// Merge: only overwrite fields that are non-empty (non-zero)
	if hostname == "" {
		hostname = existing.Hostname
	}
	if ip == "" {
		ip = existing.IPAddress
	}
	if osType == "" {
		osType = existing.OSType
	}
	if arch == "" {
		arch = existing.Arch
	}
	// hasDocker is a bool — we always use the input value (caller must pass the desired state)

	_, err = s.db.ExecContext(ctx,
		"UPDATE peers SET hostname = ?, ip_address = ?, os_type = ?, arch = ?, has_docker = ?, description = ? WHERE id = ?",
		hostname, ip, osType, arch, hasDocker, description, id)
	if err != nil {
		return fmt.Errorf("update peer: %w", err)
	}
	return nil
}

// DeletePeer deletes a peer and all its associated data in a single transaction.
func (s *PeerStore) DeletePeer(ctx context.Context, id int) error {
	return RunInTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM group_members WHERE peer_id = ?", id); err != nil {
			return fmt.Errorf("cleanup group_members: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM rule_bundles WHERE peer_id = ?", id); err != nil {
			return fmt.Errorf("cleanup rule_bundles: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM firewall_logs WHERE peer_id = ?", id); err != nil {
			// Non-fatal: firewall_logs may be in a separate logs database
			log.WarnContext(ctx, "failed to cleanup firewall_logs for peer", "peer_id", id, "error", err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM peer_ips WHERE peer_id = ?", id); err != nil {
			return fmt.Errorf("cleanup peer_ips: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM pending_changes WHERE peer_id = ?", id); err != nil {
			return fmt.Errorf("cleanup pending_changes: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM change_snapshots WHERE entity_type = 'peer' AND entity_id = ?", id); err != nil {
			return fmt.Errorf("cleanup change_snapshots: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM pending_bundle_previews WHERE peer_id = ?", id); err != nil {
			return fmt.Errorf("cleanup pending_bundle_previews: %w", err)
		}
		result, err := tx.ExecContext(ctx, "DELETE FROM peers WHERE id = ?", id)
		if err != nil {
			return fmt.Errorf("delete peer: %w", err)
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("rows affected: %w", err)
		}
		if rowsAffected == 0 {
			return sql.ErrNoRows
		}
		return nil
	})
}

func (s *PeerStore) GetPeerByID(ctx context.Context, id int) (models.PeerRow, error) {
	var p models.PeerRow
	err := s.db.QueryRowContext(ctx,
		"SELECT "+peerRowColumns+" FROM peers WHERE id = ?",
		id,
	).Scan(&p.ID, &p.Hostname, &p.IPAddress, &p.OSType, &p.Arch, &p.HasDocker,
		&p.AgentKey, &p.AgentToken, &p.AgentVersion, &p.IsManual,
		&p.BundleVersion, &p.LastHeartbeat, &p.Status, &p.CreatedAt)
	if err != nil {
		return p, fmt.Errorf("query peer by id: %w", err)
	}
	return p, nil
}

func (s *PeerStore) GetPeerByHostname(ctx context.Context, hostname string) (models.PeerRow, error) {
	var p models.PeerRow
	err := s.db.QueryRowContext(ctx,
		"SELECT "+peerRowColumns+" FROM peers WHERE hostname = ?",
		hostname,
	).Scan(&p.ID, &p.Hostname, &p.IPAddress, &p.OSType, &p.Arch, &p.HasDocker,
		&p.AgentKey, &p.AgentToken, &p.AgentVersion, &p.IsManual,
		&p.BundleVersion, &p.LastHeartbeat, &p.Status, &p.CreatedAt)
	if err != nil {
		return p, fmt.Errorf("query peer by hostname: %w", err)
	}
	return p, nil
}

// GetPeerByIP looks up a peer by IP address. It first checks the
// ip_address column, then falls back to the peer_ips table for secondary IPs.
func (s *PeerStore) GetPeerByIP(ctx context.Context, ip string) (models.PeerRow, error) {
	var p models.PeerRow
	err := s.db.QueryRowContext(ctx,
		"SELECT "+peerRowColumns+" FROM peers WHERE ip_address = ?",
		ip,
	).Scan(&p.ID, &p.Hostname, &p.IPAddress, &p.OSType, &p.Arch, &p.HasDocker,
		&p.AgentKey, &p.AgentToken, &p.AgentVersion, &p.IsManual,
		&p.BundleVersion, &p.LastHeartbeat, &p.Status, &p.CreatedAt)
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return p, fmt.Errorf("query peer by ip: %w", err)
	}

	// Fallback: check peer_ips table for secondary IPs
	err = s.db.QueryRowContext(ctx,
		"SELECT p.id, p.hostname, p.ip_address, p.os_type, p.arch, p.has_docker, p.agent_key, p.agent_token, p.agent_version, p.is_manual, p.bundle_version, p.last_heartbeat, COALESCE(p.status, ''), p.created_at FROM peers p JOIN peer_ips pi ON p.id = pi.peer_id WHERE pi.ip_address = ?",
		ip,
	).Scan(&p.ID, &p.Hostname, &p.IPAddress, &p.OSType, &p.Arch, &p.HasDocker,
		&p.AgentKey, &p.AgentToken, &p.AgentVersion, &p.IsManual,
		&p.BundleVersion, &p.LastHeartbeat, &p.Status, &p.CreatedAt)
	if err != nil {
		return p, fmt.Errorf("query peer by ip (fallback): %w", err)
	}
	return p, nil
}

func (s *PeerStore) ListPeerIPs(ctx context.Context, peerID int) ([]PeerIPView, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, peer_id, ip_address, is_primary FROM peer_ips WHERE peer_id = ? ORDER BY is_primary DESC, id ASC",
		peerID)
	if err != nil {
		return nil, fmt.Errorf("query peer IPs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ips []PeerIPView
	for rows.Next() {
		var pip PeerIPView
		var isPrimary int
		if err := rows.Scan(&pip.ID, &pip.PeerID, &pip.IPAddress, &isPrimary); err != nil {
			return nil, fmt.Errorf("scan peer IP: %w", err)
		}
		pip.IsPrimary = isPrimary == 1
		ips = append(ips, pip)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return ic.EnsureSlice(ips), nil
}

func (s *PeerStore) AddPeerIP(ctx context.Context, peerID int, ip string, isPrimary bool) error {
	isPrimaryInt := 0
	if isPrimary {
		isPrimaryInt = 1
	}
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, ?)",
		peerID, ip, isPrimaryInt)
	if err != nil {
		return fmt.Errorf("insert peer IP: %w", err)
	}
	return nil
}

// GetPeerIP returns a single peer_ip row by its own id.
// Returns (*PeerIPView, nil) on success or (nil, sql.ErrNoRows) if not found.
func (s *PeerStore) GetPeerIP(ctx context.Context, ipID int) (*PeerIPView, error) {
	var pip PeerIPView
	var isPrimary int
	err := s.db.QueryRowContext(ctx,
		"SELECT id, peer_id, ip_address, is_primary FROM peer_ips WHERE id = ?",
		ipID,
	).Scan(&pip.ID, &pip.PeerID, &pip.IPAddress, &isPrimary)
	if err != nil {
		return nil, fmt.Errorf("get peer IP: %w", err)
	}
	pip.IsPrimary = isPrimary == 1
	return &pip, nil
}

// DeletePeerIPIfOrphan deletes a peer_ip by id, but only when it is not
// referenced by any policy (as source_ip or target_ip).  Returns sql.ErrNoRows
// if the row does not exist or if policy references block the delete.
func (s *PeerStore) DeletePeerIPIfOrphan(ctx context.Context, ipID int, peerID int, ipAddress string) error {
	var refCount int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM policies WHERE (source_id = ? AND source_ip = ?) OR (target_id = ? AND target_ip = ?)",
		peerID, ipAddress, peerID, ipAddress,
	).Scan(&refCount)
	if err != nil {
		return fmt.Errorf("count policy refs: %w", err)
	}
	if refCount > 0 {
		return fmt.Errorf("peer IP %d is referenced by %d policy/policies: %w", ipID, refCount, sql.ErrNoRows)
	}
	result, err := s.db.ExecContext(ctx, "DELETE FROM peer_ips WHERE id = ?", ipID)
	if err != nil {
		return fmt.Errorf("delete peer IP: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *PeerStore) DeletePeerIP(ctx context.Context, ipID int) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM peer_ips WHERE id = ?", ipID)
	if err != nil {
		return fmt.Errorf("delete peer IP: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CountPolicyRefsForPeerIP counts policy references for a peer IP. This checks both source and target sides of policies.
func (s *PeerStore) CountPolicyRefsForPeerIP(ctx context.Context, peerID int, ip string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM policies WHERE (source_id = ? AND source_ip = ?) OR (target_id = ? AND target_ip = ?)",
		peerID, ip, peerID, ip).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count policy refs for peer IP: %w", err)
	}
	return count, nil
}

// UpsertPeerIPs inserts or ignores peer IPs. The primary IP gets is_primary = 1, all others get is_primary = 0.
// Uses INSERT OR IGNORE for duplicate safety, then updates is_primary for the primary.
func (s *PeerStore) UpsertPeerIPs(ctx context.Context, peerID int, ips []string, primaryIP string) error {
	for _, ip := range ips {
		isPrimary := 0
		if ip == primaryIP {
			isPrimary = 1
		}
		_, err := s.db.ExecContext(ctx,
			"INSERT OR IGNORE INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, ?)",
			peerID, ip, isPrimary)
		if err != nil {
			return fmt.Errorf("insert peer IP %s: %w", ip, err)
		}

		if isPrimary == 1 {
			_, err := s.db.ExecContext(ctx,
				"UPDATE peer_ips SET is_primary = 1 WHERE peer_id = ? AND ip_address = ?",
				peerID, ip)
			if err != nil {
				log.Warn("Failed to update is_primary flag", "error", err, "peer_id", peerID, "ip", ip)
			}
		}
	}
	return nil
}

// SyncPeerIPs synchronizes reported IPs with the database. It adds new IPs, removes stale IPs no longer reported (checking policy refs),
// and updates is_primary flags. Returns IDs of deleted peer_ip rows.
func (s *PeerStore) SyncPeerIPs(ctx context.Context, peerID int, ips []string, primaryIP string) ([]int64, error) {
	// First, upsert all current IPs
	if err := s.UpsertPeerIPs(ctx, peerID, ips, primaryIP); err != nil {
		return nil, err
	}

	// Build a set of reported IPs for fast lookup
	reportedSet := make(map[string]bool, len(ips))
	for _, ip := range ips {
		reportedSet[ip] = true
	}

	// Query existing IPs for this peer
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, ip_address FROM peer_ips WHERE peer_id = ?", peerID)
	if err != nil {
		return nil, fmt.Errorf("query existing peer IPs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type ipEntry struct {
		ID int64
		IP string
	}
	var existingIPs []ipEntry
	for rows.Next() {
		var entry ipEntry
		if err := rows.Scan(&entry.ID, &entry.IP); err != nil {
			continue
		}
		existingIPs = append(existingIPs, entry)
	}

	var deletedIDs []int64
	for _, entry := range existingIPs {
		if reportedSet[entry.IP] {
			continue
		}
		var refCount int
		err := s.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM policies WHERE (source_id = ? AND source_ip = ?) OR (target_id = ? AND target_ip = ?)",
			peerID, entry.IP, peerID, entry.IP).Scan(&refCount)
		if err != nil {
			log.Warn("Failed to check policy references for stale peer IP", "error", err, "peer_id", peerID, "ip", entry.IP)
			continue
		}
		if refCount > 0 {
			log.Warn("Skipping deletion of stale peer IP: referenced by active policies", "peer_id", peerID, "ip", entry.IP, "policy_count", refCount)
			continue
		}
		_, err = s.db.ExecContext(ctx, "DELETE FROM peer_ips WHERE peer_id = ? AND ip_address = ?", peerID, entry.IP)
		if err != nil {
			log.Warn("Failed to delete stale peer IP", "error", err, "peer_id", peerID, "ip", entry.IP)
			continue
		}
		deletedIDs = append(deletedIDs, entry.ID)
	}

	// Ensure only the primary IP has is_primary = 1
	_, err = s.db.ExecContext(ctx, "UPDATE peer_ips SET is_primary = 0 WHERE peer_id = ?", peerID)
	if err != nil {
		log.Warn("Failed to reset is_primary flags", "error", err, "peer_id", peerID)
	}
	if primaryIP != "" {
		_, err = s.db.ExecContext(ctx,
			"UPDATE peer_ips SET is_primary = 1 WHERE peer_id = ? AND ip_address = ?",
			peerID, primaryIP)
		if err != nil {
			log.Warn("Failed to set primary IP flag", "error", err, "peer_id", peerID, "ip", primaryIP)
		}
	}

	return ic.EnsureSlice(deletedIDs), nil
}

func (s *PeerStore) UpdatePeerHeartbeat(ctx context.Context, peerID int, agentVersion, bundleVersion string, hasIPSet *bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE peers SET last_heartbeat = CURRENT_TIMESTAMP, status = 'online', agent_version = ?, bundle_version = ?, has_ipset = ? WHERE id = ?`,
		agentVersion, bundleVersion, hasIPSet, peerID)
	if err != nil {
		return fmt.Errorf("update peer heartbeat: %w", err)
	}
	return nil
}

func (s *PeerStore) GetPeerRotationState(ctx context.Context, hostname string) (rotationToken, hmacKey string, err error) {
	var rt sql.NullString
	err = s.db.QueryRowContext(ctx,
		"SELECT hostname, hmac_key, hmac_key_rotation_token FROM peers WHERE hostname = ?",
		hostname,
	).Scan(&hostname, &hmacKey, &rt)
	if err != nil {
		return "", "", fmt.Errorf("query peer rotation state: %w", err)
	}
	if rt.Valid {
		rotationToken = rt.String
	}
	return rotationToken, hmacKey, nil
}

func (s *PeerStore) StartKeyRotation(ctx context.Context, hostname string, newHMACKey, newToken string) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE peers SET hmac_key = ?, hmac_key_rotation_token = ?, hmac_key_last_rotated_at = CURRENT_TIMESTAMP WHERE hostname = ?",
		newHMACKey, newToken, hostname)
	if err != nil {
		return fmt.Errorf("start key rotation: %w", err)
	}
	return nil
}

func (s *PeerStore) ClearRotationToken(ctx context.Context, peerID int) error {
	_, err := s.db.ExecContext(ctx, "UPDATE peers SET hmac_key_rotation_token = NULL WHERE id = ?", peerID)
	if err != nil {
		return fmt.Errorf("clear rotation token: %w", err)
	}
	return nil
}

// ClearRotationTokenTx clears the rotation token for a peer within a transaction.
func (s *PeerStore) ClearRotationTokenTx(ctx context.Context, tx *sql.Tx, peerID int) error {
	_, err := tx.ExecContext(ctx, "UPDATE peers SET hmac_key_rotation_token = NULL WHERE id = ?", peerID)
	if err != nil {
		return fmt.Errorf("clear rotation token: %w", err)
	}
	return nil
}

// ConsumeRotationTokenByID clears the rotation token for a peer.
func (s *PeerStore) ConsumeRotationTokenByID(ctx context.Context, peerID int) error {
	_, err := s.db.ExecContext(ctx, "UPDATE peers SET hmac_key_rotation_token = NULL WHERE id = ?", peerID)
	if err != nil {
		return fmt.Errorf("consume rotation token by id: %w", err)
	}
	return nil
}

// ConsumeRotationTokenByIDTx clears the rotation token for a peer within a transaction.
func (s *PeerStore) ConsumeRotationTokenByIDTx(ctx context.Context, tx *sql.Tx, peerID int) error {
	_, err := tx.ExecContext(ctx, "UPDATE peers SET hmac_key_rotation_token = NULL WHERE id = ?", peerID)
	if err != nil {
		return fmt.Errorf("consume rotation token by id: %w", err)
	}
	return nil
}

// GetHMACKeyLastRotatedAt returns the hmac_key_last_rotated_at timestamp for a peer.
func (s *PeerStore) GetHMACKeyLastRotatedAt(ctx context.Context, peerID int) (sql.NullString, error) {
	var lastRotatedAt sql.NullString
	err := s.db.QueryRowContext(ctx, "SELECT hmac_key_last_rotated_at FROM peers WHERE id = ?", peerID).Scan(&lastRotatedAt)
	if err != nil {
		return lastRotatedAt, fmt.Errorf("get hmac key last rotated at: %w", err)
	}
	return lastRotatedAt, nil
}

// GetPeerIDAndLastRotatedAt returns the peer ID and last rotation timestamp by hostname.
func (s *PeerStore) GetPeerIDAndLastRotatedAt(ctx context.Context, hostname string) (int, sql.NullString, error) {
	var peerID int
	var lastRotatedAt sql.NullString
	err := s.db.QueryRowContext(ctx, "SELECT id, hmac_key_last_rotated_at FROM peers WHERE hostname = ?", hostname).Scan(&peerID, &lastRotatedAt)
	if err != nil {
		return 0, lastRotatedAt, fmt.Errorf("get peer id and last rotated at: %w", err)
	}
	return peerID, lastRotatedAt, nil
}

func (s *PeerStore) ConfirmRotation(ctx context.Context, hostname string) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE peers SET hmac_key_last_rotated_at = CURRENT_TIMESTAMP WHERE hostname = ?",
		hostname)
	if err != nil {
		return fmt.Errorf("confirm rotation: %w", err)
	}
	return nil
}

// getPendingBundleInfo returns the latest (pending) bundle data and the deployed version
// for a peer. This is the shared query pattern used by both GetPeerBundle and
// GetPeerBundleWithDeployed.
func (s *PeerStore) getPendingBundleInfo(ctx context.Context, peerID int) (rulesContent, version, hmac, deployedVersion string, versionNumber int, err error) {
	err = s.db.QueryRowContext(ctx,
		"SELECT rules_content, version, version_number, hmac FROM rule_bundles WHERE peer_id = ? ORDER BY created_at DESC LIMIT 1",
		peerID,
	).Scan(&rulesContent, &version, &versionNumber, &hmac)
	if err != nil {
		return "", "", "", "", 0, fmt.Errorf("query pending bundle: %w", err)
	}

	var dv sql.NullString
	err = s.db.QueryRowContext(ctx,
		"SELECT bundle_version FROM peers WHERE id = ?", peerID,
	).Scan(&dv)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", "", "", "", 0, fmt.Errorf("query deployed version: %w", err)
	}
	if dv.Valid {
		deployedVersion = dv.String
	}
	return rulesContent, version, hmac, deployedVersion, versionNumber, nil
}

// GetPeerBundleWithDeployed returns both the pending (latest) and deployed bundle data
// in a single call, avoiding the double-query pattern (T007-#1).
// Returns pendingData, deployedData, pendingVersion, pendingVersionNumber, pendingHMAC, deployedVersion, error.
func (s *PeerStore) GetPeerBundleWithDeployed(ctx context.Context, peerID int) (pendingData, deployedData, version, hmac, deployedVersion string, versionNumber int, err error) {
	pendingData, version, hmac, deployedVersion, versionNumber, err = s.getPendingBundleInfo(ctx, peerID)
	if err != nil {
		return "", "", "", "", "", 0, err
	}

	// Get deployed bundle data if a deployed version exists
	if deployedVersion != "" {
		err = s.db.QueryRowContext(ctx,
			`SELECT rules_content FROM rule_bundles WHERE peer_id = ? AND version = ? ORDER BY created_at DESC LIMIT 1`,
			peerID, deployedVersion,
		).Scan(&deployedData)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return "", "", "", "", "", 0, fmt.Errorf("query deployed bundle: %w", err)
		}
		if errors.Is(err, sql.ErrNoRows) {
			deployedData = ""
		}
	}

	return pendingData, deployedData, version, hmac, deployedVersion, versionNumber, nil
}

// GetPeerBundle returns the rule bundle for a peer. If includePending is true,
// it returns the latest bundle; otherwise it returns the deployed bundle
// matching the peer's bundle_version.
// Returns bundleData (rules_content), version, versionNumber, hmac, deployedVersion, and any error.
func (s *PeerStore) GetPeerBundle(ctx context.Context, peerID int, includePending bool) (bundleData string, version string, versionNumber int, hmac string, deployedVersion string, err error) {
	if includePending {
		bundleData, version, hmac, deployedVersion, versionNumber, err = s.getPendingBundleInfo(ctx, peerID)
		if err != nil {
			return "", "", 0, "", "", err
		}
		return bundleData, version, versionNumber, hmac, deployedVersion, nil
	}

	// Deployed bundle mode
	err = s.db.QueryRowContext(ctx,
		`SELECT rb.rules_content, rb.version, rb.version_number, rb.hmac
		FROM rule_bundles rb
		JOIN peers p ON p.id = ?
		WHERE rb.version = p.bundle_version AND rb.peer_id = p.id
		ORDER BY rb.created_at DESC LIMIT 1`, peerID,
	).Scan(&bundleData, &version, &versionNumber, &hmac)
	if err != nil {
		return "", "", 0, "", "", fmt.Errorf("query deployed bundle: %w", err)
	}

	return bundleData, version, versionNumber, hmac, "", nil
}

func (s *PeerStore) UpdatePeerBundleVersion(ctx context.Context, peerID int, version string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE peers SET bundle_version = ? WHERE id = ?", version, peerID)
	if err != nil {
		return fmt.Errorf("update peer bundle version: %w", err)
	}
	return nil
}

// UpdatePeerBundleVersionTx updates the peer bundle version within a transaction.
func (s *PeerStore) UpdatePeerBundleVersionTx(ctx context.Context, tx *sql.Tx, peerID int, version string) error {
	_, err := tx.ExecContext(ctx, "UPDATE peers SET bundle_version = ? WHERE id = ?", version, peerID)
	if err != nil {
		return fmt.Errorf("update peer bundle version tx: %w", err)
	}
	return nil
}

// UpdateBundleAppliedAtTx updates the bundle applied_at and first_applied_at within a transaction.
func (s *PeerStore) UpdateBundleAppliedAtTx(ctx context.Context, tx *sql.Tx, peerID int, version string, appliedAt string) error {
	_, err := tx.ExecContext(ctx, `UPDATE rule_bundles SET applied_at = ?, first_applied_at = COALESCE(first_applied_at, ?) WHERE peer_id = ? AND version = ?`, appliedAt, appliedAt, peerID, version)
	if err != nil {
		return fmt.Errorf("update bundle applied_at tx: %w", err)
	}
	return nil
}

func (s *PeerStore) UpdatePeerAgentVersion(ctx context.Context, peerID int, version string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE peers SET agent_version = ? WHERE id = ?", version, peerID)
	if err != nil {
		return fmt.Errorf("update peer agent version: %w", err)
	}
	return nil
}

func (s *PeerStore) GetPeerHostname(ctx context.Context, peerID int) (string, error) {
	var hostname string
	err := s.db.QueryRowContext(ctx, "SELECT hostname FROM peers WHERE id = ?", peerID).Scan(&hostname)
	if err != nil {
		return "", fmt.Errorf("get peer hostname: %w", err)
	}
	return hostname, nil
}

func (s *PeerStore) GetPeerPrimaryIP(ctx context.Context, peerID int) (string, error) {
	var ip string
	err := s.db.QueryRowContext(ctx, "SELECT ip_address FROM peers WHERE id = ?", peerID).Scan(&ip)
	if err != nil {
		return "", fmt.Errorf("get peer primary IP: %w", err)
	}
	return ip, nil
}

func (s *PeerStore) GetPeerHMACKey(ctx context.Context, peerID int) (string, error) {
	var hmacKey string
	err := s.db.QueryRowContext(ctx, "SELECT hmac_key FROM peers WHERE id = ?", peerID).Scan(&hmacKey)
	if err != nil {
		return "", fmt.Errorf("get peer HMAC key: %w", err)
	}
	return hmacKey, nil
}

func (s *PeerStore) GetPeerRotationToken(ctx context.Context, peerID int) (sql.NullString, error) {
	var token sql.NullString
	err := s.db.QueryRowContext(ctx, "SELECT hmac_key_rotation_token FROM peers WHERE id = ?", peerID).Scan(&token)
	if err != nil {
		return token, fmt.Errorf("get peer rotation token: %w", err)
	}
	return token, nil
}

// FindPeerByHostname finds a peer by hostname. Returns sql.ErrNoRows if no peer is found.
func (s *PeerStore) FindPeerByHostname(ctx context.Context, hostname string) (id int, token sql.NullString, err error) {
	err = s.db.QueryRowContext(ctx, "SELECT id, agent_token FROM peers WHERE hostname = ?", hostname).Scan(&id, &token)
	if err != nil {
		return 0, token, fmt.Errorf("find peer by hostname: %w", err)
	}
	return id, token, nil
}

func (s *PeerStore) GetPeerIDByHostname(ctx context.Context, hostname string) (int, error) {
	var id int
	err := s.db.QueryRowContext(ctx, "SELECT id FROM peers WHERE hostname = ?", hostname).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("get peer ID by hostname: %w", err)
	}
	return id, nil
}

// GetLatestBundle returns the most recent rule bundle for a peer. Returns sql.ErrNoRows if no bundle is found.
func (s *PeerStore) GetLatestBundle(ctx context.Context, peerID int) (models.RuleBundleRow, error) {
	var bundle models.RuleBundleRow
	err := s.db.QueryRowContext(ctx,
		"SELECT "+ruleBundleRowColumns+" FROM rule_bundles WHERE peer_id = ? ORDER BY created_at DESC LIMIT 1",
		peerID,
	).Scan(&bundle.ID, &bundle.PeerID, &bundle.Version, &bundle.VersionNumber, &bundle.RulesContent, &bundle.HMAC, &bundle.CreatedAt, &bundle.AppliedAt, &bundle.FirstAppliedAt)
	if err != nil {
		return bundle, fmt.Errorf("get latest bundle: %w", err)
	}
	return bundle, nil
}

func (s *PeerStore) UpdateBundleAppliedAt(ctx context.Context, peerID int, version string, appliedAt string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE rule_bundles SET applied_at = ?, first_applied_at = COALESCE(first_applied_at, ?) WHERE peer_id = ? AND version = ?`, appliedAt, appliedAt, peerID, version)
	if err != nil {
		return fmt.Errorf("update bundle applied_at: %w", err)
	}
	return nil
}

func (s *PeerStore) RegisterPeer(ctx context.Context, hostname, ip, osType, arch string, hasDocker bool, hasIPSet *bool, agentKey, agentToken, hmacKey string) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, has_ipset, agent_key, agent_token, hmac_key, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'online')`,
		hostname, ip, osType, arch, hasDocker, hasIPSet, agentKey, agentToken, hmacKey)
	if err != nil {
		return 0, fmt.Errorf("register peer: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get insert id: %w", err)
	}
	return id, nil
}

// GetPeerWithIP returns the hostname and IP address for a peer by ID.
// Returns sql.ErrNoRows if the peer is not found.
func (s *PeerStore) GetPeerWithIP(ctx context.Context, peerID int) (hostname string, ipAddress string, err error) {
	err = s.db.QueryRowContext(ctx, "SELECT hostname, ip_address FROM peers WHERE id = ?", peerID).Scan(&hostname, &ipAddress)
	if err != nil {
		return "", "", fmt.Errorf("get peer with IP: %w", err)
	}
	return hostname, ipAddress, nil
}

// GetPeerWithAgentVersion returns the hostname, agent version, and is_manual flag for a peer by ID.
// Returns sql.ErrNoRows if the peer is not found.
func (s *PeerStore) GetPeerWithAgentVersion(ctx context.Context, peerID int) (hostname string, agentVersion sql.NullString, isManual bool, err error) {
	err = s.db.QueryRowContext(ctx, "SELECT hostname, agent_version, is_manual FROM peers WHERE id = ?", peerID).Scan(&hostname, &agentVersion, &isManual)
	if err != nil {
		return "", agentVersion, false, fmt.Errorf("get peer with agent version: %w", err)
	}
	return hostname, agentVersion, isManual, nil
}

// ListAgentBasedPeers returns all non-manual (agent-based) peers, ordered by hostname.
func (s *PeerStore) ListAgentBasedPeers(ctx context.Context) ([]PeerView, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, hostname FROM peers WHERE is_manual = 0 ORDER BY hostname")
	if err != nil {
		return nil, fmt.Errorf("query agent-based peers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var peers []PeerView
	for rows.Next() {
		var p PeerView
		if err := rows.Scan(&p.ID, &p.Hostname); err != nil {
			return nil, fmt.Errorf("scan agent-based peer: %w", err)
		}
		peers = append(peers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return ic.EnsureSlice(peers), nil
}

// CheckDeleteConstraints checks whether a peer can be safely deleted.
// It checks:
// 1. If the peer is explicitly a target_id (and type='peer') or source_id (and type='peer')
// 2. If the peer is in a group that is used by a policy
// Returns a *common.DeleteConstraintError containing all policies that reference the peer.
func (s *PeerStore) CheckDeleteConstraints(ctx context.Context, peerID int) error {
	var policies []common.PolicyRef

	// Check direct peer references in policies
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name FROM policies
		WHERE ((target_type='peer' AND target_id=?) OR (source_type='peer' AND source_id=?)) AND is_pending_delete = 0`,
		peerID, peerID,
	)
	if err != nil {
		return fmt.Errorf("failed to query peer policies: %w", err)
	}
	for rows.Next() {
		var ref common.PolicyRef
		if scanErr := rows.Scan(&ref.ID, &ref.Name); scanErr == nil {
			policies = append(policies, ref)
		}
	}
	if closeErr := rows.Close(); closeErr != nil {
		return fmt.Errorf("failed to close rows: %w", closeErr)
	}

	// Check peer via group references in policies
	rows, err = s.db.QueryContext(ctx, `
		SELECT DISTINCT p.id, p.name FROM policies p
		JOIN group_members gm ON (gm.group_id = p.source_id AND p.source_type='group') OR (gm.group_id = p.target_id AND p.target_type='group')
		WHERE gm.peer_id = ? AND p.is_pending_delete = 0
	`, peerID)
	if err != nil {
		return fmt.Errorf("failed to query group policies: %w", err)
	}
	for rows.Next() {
		var ref common.PolicyRef
		if scanErr := rows.Scan(&ref.ID, &ref.Name); scanErr == nil {
			policies = append(policies, ref)
		}
	}
	if closeErr := rows.Close(); closeErr != nil {
		return fmt.Errorf("failed to close rows: %w", closeErr)
	}

	if len(policies) > 0 {
		return &common.DeleteConstraintError{
			Message:  "cannot delete peer — it is in use by one or more policies",
			Policies: policies,
		}
	}

	return nil
}

// GetLatestBundleForPeer returns the most recent rule bundle's content, version, and version number for a peer.
// Returns sql.ErrNoRows if no bundle is found.
func (s *PeerStore) GetLatestBundleForPeer(ctx context.Context, peerID int) (rulesContent string, version string, versionNumber int, err error) {
	err = s.db.QueryRowContext(ctx,
		"SELECT rules_content, version, version_number FROM rule_bundles WHERE peer_id = ? ORDER BY id DESC LIMIT 1",
		peerID).Scan(&rulesContent, &version, &versionNumber)
	if err != nil {
		return "", "", 0, fmt.Errorf("get latest bundle for peer: %w", err)
	}
	return rulesContent, version, versionNumber, nil
}

// GetNextBundleVersionNumber computes the next version number for a peer's rule bundle.
// Returns 1 if no bundles exist yet.
func (s *PeerStore) GetNextBundleVersionNumber(ctx context.Context, peerID int) (int, error) {
	var versionNumber int
	err := s.db.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(version_number), 0) + 1 FROM rule_bundles WHERE peer_id = ?",
		peerID).Scan(&versionNumber)
	if err != nil {
		return 0, fmt.Errorf("get next bundle version number: %w", err)
	}
	return versionNumber, nil
}

// CheckPendingChangeExists checks whether a pending change exists for a specific peer and entity.
func (s *PeerStore) CheckPendingChangeExists(ctx context.Context, peerID int, changeType string, changeID int) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx,
		"SELECT 1 FROM pending_changes WHERE peer_id = ? AND change_type = ? AND change_id = ?",
		peerID, changeType, changeID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check pending change exists: %w", err)
	}
	return true, nil
}

func (s *PeerStore) UpdatePeerReRegistration(ctx context.Context, peerID int, agentToken, agentVersion string, hasDocker bool, hasIPSet *bool) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE peers SET agent_token = ?, status = 'online', agent_version = ?, has_docker = ?, has_ipset = ? WHERE id = ?",
		agentToken, agentVersion, hasDocker, hasIPSet, peerID)
	if err != nil {
		return fmt.Errorf("update peer re-registration: %w", err)
	}
	return nil
}
