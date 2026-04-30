// Package db provides database interactions.
package db

import (
	"context"

	"runic/internal/common/log"
	"runic/internal/models"
)

// ListGroupMembers fetches all members of a group.
func ListGroupMembers(ctx context.Context, database Querier, groupID int) ([]models.GroupMemberRow, error) {
	rows, err := database.QueryContext(ctx,
		"SELECT id, group_id, peer_id, added_at FROM group_members WHERE group_id = ?", groupID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.WarnContext(ctx, "failed to close rows", "error", err)
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
