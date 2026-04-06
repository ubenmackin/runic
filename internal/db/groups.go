// Package db provides database interactions.
package db

import (
	"context"
	"fmt"

	"runic/internal/models"
)

// GetGroup fetches a group by ID.
func GetGroup(ctx context.Context, database Querier, groupID int) (models.GroupRow, error) {
	var g models.GroupRow
	err := database.QueryRowContext(ctx,
		"SELECT id, name, COALESCE(description, ''), COALESCE(is_system, 0) FROM groups WHERE id = ?", groupID,
	).Scan(&g.ID, &g.Name, &g.Description, &g.IsSystem)
	return g, err
}

// ListGroupMembers fetches all members of a group.
func ListGroupMembers(ctx context.Context, database Querier, groupID int) ([]models.GroupMemberRow, error) {
	rows, err := database.QueryContext(ctx,
		"SELECT id, group_id, peer_id, added_at FROM group_members WHERE group_id = ?", groupID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cErr := rows.Close(); cErr != nil {
			fmt.Printf("failed to close rows: %v\n", cErr)
		}
	}()

	var members []models.GroupMemberRow
	for rows.Next() {
		var m models.GroupMemberRow
		if err := rows.Scan(&m.ID, &m.GroupID, &m.PeerID, &m.AddedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

// FindPoliciesByGroupID finds policies by source target group id.
func FindPoliciesByGroupID(ctx context.Context, database Querier, groupID int) ([]models.PolicyRow, error) {
	rows, err := database.QueryContext(ctx,
		`SELECT id, name, COALESCE(description, ''), source_id, source_type, service_id, target_id, target_type,
		action, priority, enabled, target_scope, COALESCE(direction, 'both'), created_at, updated_at
		FROM policies
		WHERE (source_type = 'group' AND source_id = ?) OR (target_type = 'group' AND target_id = ?)`, groupID, groupID)
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
