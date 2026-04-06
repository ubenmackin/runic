package db

import (
	"context"
	"fmt"

	"runic/internal/models"
)

// ListEnabledPolicies fetches enabled policies for a target peer (direct or group member), ordered by priority ASC.
func ListEnabledPolicies(ctx context.Context, database Querier, peerID int) ([]models.PolicyRow, error) {
	// A policy applies to a peer if the target is exactly the peer (target_type='peer' AND target_id=peerID)
	// OR if the target is a group containing the peer (target_type='group' AND target_id IN group_members where peer_id=peerID).
	rows, err := database.QueryContext(ctx,
		`SELECT DISTINCT p.id, p.name, COALESCE(p.description, ''), p.source_id, p.source_type, p.service_id, p.target_id, p.target_type,
		p.action, p.priority, p.enabled, p.target_scope, COALESCE(p.direction, 'both'), p.created_at, p.updated_at
		FROM policies p
		LEFT JOIN group_members gm ON p.target_type = 'group' AND p.target_id = gm.group_id
		WHERE p.enabled = 1 AND (
			(p.target_type = 'peer' AND p.target_id = ?) OR
			(p.target_type = 'group' AND gm.peer_id = ?)
		)
		ORDER BY p.priority ASC`, peerID, peerID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cErr := rows.Close(); cErr != nil {
			fmt.Printf("failed to close rows: %v\n", cErr)
		}
	}()

	var policies []models.PolicyRow
	for rows.Next() {
		var p models.PolicyRow
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.SourceID, &p.SourceType, &p.ServiceID,
			&p.TargetID, &p.TargetType, &p.Action, &p.Priority, &p.Enabled, &p.TargetScope, &p.Direction, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}
