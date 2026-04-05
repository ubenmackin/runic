package common

import (
	"context"
	"fmt"

	"runic/internal/db"
)

// CheckPeerDeleteConstraints returns an error if the peer is in use by any policy.
// It checks:
// 1. If the peer is explicitly a target_id (and type='peer') or source_id (and type='peer')
// 2. If the peer is in a group that is used by a policy
func CheckPeerDeleteConstraints(ctx context.Context, database db.Querier, peerID int) error {
	// Check 1: Explicit Peer Policy
	var policyName string
	err := database.QueryRowContext(ctx,
		`SELECT name FROM policies
		WHERE (target_type='peer' AND target_id=?) OR (source_type='peer' AND source_id=?)
		ORDER BY id LIMIT 1`, peerID, peerID,
	).Scan(&policyName)
	if err == nil {
		return fmt.Errorf("Cannot delete peer — it is explicitly targeted in policy '%s'", policyName)
	}

	// Check 2: Group Policy
	err = database.QueryRowContext(ctx, `
		SELECT p.name FROM policies p
		JOIN group_members gm ON (gm.group_id = p.source_id AND p.source_type='group') OR (gm.group_id = p.target_id AND p.target_type='group')
		WHERE gm.peer_id = ? ORDER BY p.id LIMIT 1
	`, peerID).Scan(&policyName)
	if err == nil {
		return fmt.Errorf("Cannot delete peer — it is in group used by policy '%s'", policyName)
	}

	return nil
}

// CheckGroupDeleteConstraints returns an error if the group is in use by any policy.
// It checks if the group is used as a source or target in any policy.
func CheckGroupDeleteConstraints(ctx context.Context, database db.Querier, groupID int) error {
	var policyName string
	err := database.QueryRowContext(ctx,
		`SELECT name FROM policies
		WHERE (source_type='group' AND source_id=?) OR (target_type='group' AND target_id=?)
		ORDER BY id LIMIT 1`, groupID, groupID,
	).Scan(&policyName)
	if err == nil {
		return fmt.Errorf("Cannot delete group — it is used by policy '%s'", policyName)
	}

	return nil
}
