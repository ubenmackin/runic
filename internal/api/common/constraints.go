package common

import (
	"context"
	"database/sql"
	"fmt"
)

// CheckPeerDeleteConstraints returns an error if the peer is in use by any policy.
// It checks:
// 1. If the peer is the target_peer_id in any policy
// 2. If the peer is in a group that is used as source_group_id in any policy
func CheckPeerDeleteConstraints(ctx context.Context, db *sql.DB, peerID int) error {
	// Check 1: target_peer_id in policies
	var policyName string
	err := db.QueryRowContext(ctx,
		`SELECT name FROM policies WHERE target_peer_id = ? LIMIT 1`, peerID,
	).Scan(&policyName)
	if err == nil {
		return fmt.Errorf("Cannot delete peer — it is the target of policy '%s'", policyName)
	}

	// Check 2: peer in group used as source_group_id
	err = db.QueryRowContext(ctx, `
		SELECT p.name FROM policies p
		JOIN group_members gm ON p.source_group_id = gm.group_id
		WHERE gm.peer_id = ? LIMIT 1
	`, peerID).Scan(&policyName)
	if err == nil {
		return fmt.Errorf("Cannot delete peer — it is in group used by policy '%s'", policyName)
	}

	return nil
}

// CheckGroupDeleteConstraints returns an error if the group is in use by any policy.
// It checks if the group is used as source_group_id in any policy.
func CheckGroupDeleteConstraints(ctx context.Context, db *sql.DB, groupID int) error {
	var policyName string
	err := db.QueryRowContext(ctx,
		`SELECT name FROM policies WHERE source_group_id = ? LIMIT 1`, groupID,
	).Scan(&policyName)
	if err == nil {
		return fmt.Errorf("Cannot delete group — it is used by policy '%s'", policyName)
	}

	return nil
}
