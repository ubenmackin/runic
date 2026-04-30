// Package store provides data access layer for groups, policies, and transactions.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"runic/internal/common"
	"runic/internal/db"
	"runic/internal/models"
)

// GroupWithCounts represents a group with peer and policy counts
type GroupWithCounts struct {
	ID              int    `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	IsSystem        bool   `json:"is_system"`
	IsPendingDelete bool   `json:"is_pending_delete"`
	PeerCount       int    `json:"peer_count"`
	PolicyCount     int    `json:"policy_count"`
}

// PeerInGroup represents a peer that belongs to a group
type PeerInGroup struct {
	ID        int    `json:"id"`
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ip_address"`
	OSType    string `json:"os_type"`
	IsManual  bool   `json:"is_manual"`
}

// GroupSnapshotData represents the payload of a group snapshot.
type GroupSnapshotData struct {
	Group   *models.GroupRow        `json:"group"`
	Members []models.GroupMemberRow `json:"members"`
}

type GroupStore struct {
	db db.Querier
}

func NewGroupStore(database db.Querier) *GroupStore {
	return &GroupStore{db: database}
}

func (s *GroupStore) ListGroups(ctx context.Context) ([]GroupWithCounts, error) {
	query := `
	SELECT g.id, g.name, COALESCE(g.description, ''), COALESCE(g.is_system, 0), COALESCE(g.is_pending_delete, 0),
	COALESCE(p.peer_count, 0), COALESCE(pol.policy_count, 0)
	FROM groups g
	LEFT JOIN (SELECT group_id, COUNT(*) as peer_count FROM group_members GROUP BY group_id) p ON g.id = p.group_id
	LEFT JOIN (
		SELECT group_id, SUM(count) as policy_count FROM (
			SELECT source_id as group_id, COUNT(*) as count FROM policies WHERE source_type='group' GROUP BY source_id
			UNION ALL
			SELECT target_id as group_id, COUNT(*) as count FROM policies WHERE target_type='group' GROUP BY target_id
		) GROUP BY group_id
	) pol ON g.id = pol.group_id
	ORDER BY g.name ASC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query groups: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var groupsData []GroupWithCounts
	for rows.Next() {
		var g GroupWithCounts
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.IsSystem, &g.IsPendingDelete, &g.PeerCount, &g.PolicyCount); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		groupsData = append(groupsData, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return common.EnsureSlice(groupsData), nil
}

func (s *GroupStore) CreateGroup(ctx context.Context, name, description string) (int64, error) {
	result, err := s.db.ExecContext(ctx, "INSERT INTO groups (name, description) VALUES (?, ?)", name, description)
	if err != nil {
		return 0, fmt.Errorf("insert group: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get insert id: %w", err)
	}
	return id, nil
}

func (s *GroupStore) GetGroup(ctx context.Context, id int) (models.GroupRow, error) {
	return s.GetGroupTx(ctx, s.db, id)
}

func (s *GroupStore) GetGroupTx(ctx context.Context, q db.Querier, id int) (models.GroupRow, error) {
	var g models.GroupRow
	err := q.QueryRowContext(ctx,
		"SELECT id, name, COALESCE(description, ''), COALESCE(is_system, 0), COALESCE(is_pending_delete, 0) FROM groups WHERE id = ? AND is_pending_delete = 0", id,
	).Scan(&g.ID, &g.Name, &g.Description, &g.IsSystem, &g.IsPendingDelete)
	if err != nil {
		return g, fmt.Errorf("query group tx: %w", err)
	}
	return g, nil
}

func (s *GroupStore) UpdateGroup(ctx context.Context, q db.Querier, id int, name, description string) error {
	result, err := q.ExecContext(ctx,
		"UPDATE groups SET name = COALESCE(NULLIF(?, ''), name), description = ? WHERE id = ? AND is_pending_delete = 0",
		name, description, id)
	if err != nil {
		return fmt.Errorf("update group: %w", err)
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

func (s *GroupStore) GetGroupSystemStatus(ctx context.Context, id int) (bool, error) {
	var isSystem bool
	err := s.db.QueryRowContext(ctx, "SELECT COALESCE(is_system, 0) FROM groups WHERE id = ? AND is_pending_delete = 0", id).Scan(&isSystem)
	if err != nil {
		return false, fmt.Errorf("query system status: %w", err)
	}
	return isSystem, nil
}

func (s *GroupStore) SoftDeleteGroup(ctx context.Context, id int) error {
	res, err := s.db.ExecContext(ctx, "UPDATE groups SET is_pending_delete = 1 WHERE id = ? AND is_pending_delete = 0", id)
	if err != nil {
		return fmt.Errorf("soft delete group: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *GroupStore) ListGroupMembers(ctx context.Context, id int) ([]PeerInGroup, error) {
	query := `
	SELECT p.id, p.hostname, p.ip_address, p.os_type, p.is_manual
	FROM peers p
	JOIN group_members gm ON p.id = gm.peer_id
	JOIN groups g ON gm.group_id = g.id
	WHERE gm.group_id = ? AND g.is_pending_delete = 0
	ORDER BY p.hostname ASC`

	rows, err := s.db.QueryContext(ctx, query, id)
	if err != nil {
		return nil, fmt.Errorf("query members: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var peers []PeerInGroup
	for rows.Next() {
		var p PeerInGroup
		if err := rows.Scan(&p.ID, &p.Hostname, &p.IPAddress, &p.OSType, &p.IsManual); err != nil {
			return nil, fmt.Errorf("scan peer: %w", err)
		}
		peers = append(peers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return common.EnsureSlice(peers), nil
}

func (s *GroupStore) AddGroupMember(ctx context.Context, groupID, peerID int) (int64, error) {
	result, err := s.db.ExecContext(ctx, "INSERT OR IGNORE INTO group_members (group_id, peer_id) VALUES (?, ?)", groupID, peerID)
	if err != nil {
		return 0, fmt.Errorf("insert member: %w", err)
	}
	// Note: When INSERT OR IGNORE silently skips a duplicate row, LastInsertId() returns 0.
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get insert id: %w", err)
	}
	return id, nil
}

func (s *GroupStore) DeleteGroupMember(ctx context.Context, groupID, peerID int) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM group_members WHERE group_id = ? AND peer_id = ?", groupID, peerID)
	if err != nil {
		return fmt.Errorf("delete member: %w", err)
	}
	return nil
}

func (s *GroupStore) GetPeerHostname(ctx context.Context, peerID int64) (string, error) {
	var hostname string
	err := s.db.QueryRowContext(ctx, "SELECT hostname FROM peers WHERE id = ?", peerID).Scan(&hostname)
	if err != nil {
		return "", fmt.Errorf("query peer hostname: %w", err)
	}
	return hostname, nil
}

// Snapshot creates a snapshot of the group and its members.
// The q parameter allows it to be used inside or outside a transaction.
func (s *GroupStore) Snapshot(ctx context.Context, q db.Querier, action string, groupID int) error {
	if action == "create" {
		return db.CreateSnapshot(ctx, q, "group", groupID, action, "")
	}

	grp, err := s.GetGroupTx(ctx, q, groupID)
	if err != nil {
		return fmt.Errorf("get group: %w", err)
	}

	members, err := db.ListGroupMembers(ctx, q, groupID)
	if err != nil {
		return fmt.Errorf("query members: %w", err)
	}

	data := GroupSnapshotData{
		Group:   &grp,
		Members: members,
	}
	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	return db.CreateSnapshot(ctx, q, "group", groupID, action, string(bytes))
}
