package db

import (
	"context"
	"database/sql"
	"fmt"

	"runic/internal/models"
)

// GetPeer fetches a peer by ID.
func GetPeer(ctx context.Context, database Querier, peerID int) (models.PeerRow, error) {
	var p models.PeerRow
	err := database.QueryRowContext(ctx,
		`SELECT id, hostname, ip_address, os_type, arch, has_docker, agent_key,
		agent_token, agent_version, is_manual, bundle_version, last_heartbeat, status, created_at
		FROM peers WHERE id = ?`, peerID,
	).Scan(&p.ID, &p.Hostname, &p.IPAddress, &p.OSType, &p.Arch, &p.HasDocker,
		&p.AgentKey, &p.AgentToken, &p.AgentVersion, &p.IsManual, &p.BundleVersion,
		&p.LastHeartbeat, &p.Status, &p.CreatedAt)
	return p, err
}

// SaveBundle inserts a new rule bundle and updates the peer's bundle_version.
func SaveBundle(ctx context.Context, database *sql.DB, params models.CreateBundleParams) (models.RuleBundleRow, error) {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return models.RuleBundleRow{}, err
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	result, err := tx.ExecContext(ctx,
		`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac) VALUES (?, ?, ?, ?, ?)`,
		params.PeerID, params.Version, params.VersionNumber, params.RulesContent, params.HMAC)
	if err != nil {
		return models.RuleBundleRow{}, err
	}

	bundleID, err := result.LastInsertId()
	if err != nil {
		return models.RuleBundleRow{}, fmt.Errorf("get last insert id: %w", err)
	}

	_, err = tx.ExecContext(ctx, `UPDATE peers SET bundle_version = ? WHERE id = ?`, params.Version, params.PeerID)
	if err != nil {
		return models.RuleBundleRow{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.RuleBundleRow{}, err
	}
	committed = true

	return models.RuleBundleRow{
		ID:            int(bundleID),
		PeerID:        params.PeerID,
		Version:       params.Version,
		VersionNumber: params.VersionNumber,
		RulesContent:  params.RulesContent,
		HMAC:          params.HMAC,
	}, nil
}
