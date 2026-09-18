// Package store provides data access layer for groups, policies, and transactions.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"runic/internal/change"
	ic "runic/internal/common"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
	"runic/internal/models"
)

const groupRowColumns = `id, name, COALESCE(description, ''), COALESCE(is_system, 0), COALESCE(is_pending_delete, 0)`

var ErrGroupNotFound = errors.New("group not found")

type GroupWithCounts struct {
	ID              int    `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	IsSystem        bool   `json:"is_system"`
	IsPendingDelete bool   `json:"is_pending_delete"`
	PeerCount       int    `json:"peer_count"`
	PolicyCount     int    `json:"policy_count"`
}

type PeerInGroup struct {
	ID        int    `json:"id"`
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ip_address"`
	OSType    string `json:"os_type"`
	IsManual  bool   `json:"is_manual"`
}

type GroupSnapshotData struct {
	Group   *models.GroupRow        `json:"group"`
	Members []models.GroupMemberRow `json:"members"`
}

type GroupStore struct {
	db db.DB
}

func NewGroupStore(database db.DB) *GroupStore {
	return &GroupStore{db: database}
}

// GetNameByID returns the group name for a given ID. Returns sql.ErrNoRows if not found.
func (s *GroupStore) GetNameByID(ctx context.Context, id int) (string, error) {
	return getNameByID(ctx, s.db, "groups", id, "", "group")
}

// GetActiveGroupNameByID returns the group name for a given ID, excluding pending-delete groups.
// Returns sql.ErrNoRows if not found or if the group is pending delete.
func (s *GroupStore) GetActiveGroupNameByID(ctx context.Context, id int) (string, error) {
	return getNameByID(ctx, s.db, "groups", id, " AND is_pending_delete = 0", "active group")
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
	WHERE g.is_pending_delete = 0
	ORDER BY g.name ASC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query groups: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.WarnContext(ctx, "failed to close rows", "error", cerr)
		}
	}()

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
	return ic.EnsureSlice(groupsData), nil
}

func (s *GroupStore) CreateGroup(ctx context.Context, name, description string) (int64, error) {
	if name == "" {
		return 0, errors.New("group name is required")
	}
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
		"SELECT "+groupRowColumns+" FROM groups WHERE id = ? AND is_pending_delete = 0", id,
	).Scan(&g.ID, &g.Name, &g.Description, &g.IsSystem, &g.IsPendingDelete)
	if err != nil {
		return g, fmt.Errorf("query group tx: %w", err)
	}
	return g, nil
}

func (s *GroupStore) UpdateGroup(ctx context.Context, id int, name, description string) error {
	return execUpdate(ctx, s.db,
		"UPDATE groups SET name = COALESCE(NULLIF(?, ''), name), description = ? WHERE id = ? AND is_pending_delete = 0",
		ErrGroupNotFound, name, description, id)
}

func (s *GroupStore) UpdateGroupTx(ctx context.Context, tx *sql.Tx, id int, name, description string) error {
	return execUpdate(ctx, tx,
		"UPDATE groups SET name = COALESCE(NULLIF(?, ''), name), description = ? WHERE id = ? AND is_pending_delete = 0",
		ErrGroupNotFound, name, description, id)
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
	return softDelete(ctx, s.db, "groups", id, ErrGroupNotFound)
}

func (s *GroupStore) SoftDeleteGroupTx(ctx context.Context, tx *sql.Tx, id int) error {
	return softDelete(ctx, tx, "groups", id, ErrGroupNotFound)
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
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.WarnContext(ctx, "failed to close rows", "error", cerr)
		}
	}()

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
	return ic.EnsureSlice(peers), nil
}

func (s *GroupStore) AddGroupMember(ctx context.Context, groupID, peerID int) (int64, error) {
	return addGroupMember(ctx, s.db, groupID, peerID)
}

func addGroupMember(ctx context.Context, q db.Querier, groupID, peerID int) (int64, error) {
	result, err := q.ExecContext(ctx, "INSERT OR IGNORE INTO group_members (group_id, peer_id) VALUES (?, ?)", groupID, peerID)
	if err != nil {
		return 0, fmt.Errorf("insert member: %w", err)
	}
	// INSERT OR IGNORE skips duplicates without error. LastInsertId is
	// unreliable for ignored rows (it may return a prior id), so detect
	// duplicates via RowsAffected: 0 means the membership already exists.
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("get rows affected: %w", err)
	}
	if affected == 0 {
		return 0, nil
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get insert id: %w", err)
	}
	return id, nil
}

func (s *GroupStore) DeleteGroupMember(ctx context.Context, groupID, peerID int) (bool, error) {
	return deleteGroupMember(ctx, s.db, groupID, peerID)
}

// AddGroupMemberTx inserts a group membership within a transaction so the
// pre-mutation snapshot and the insert commit atomically (no orphan
// snapshot on insert failure).
func (s *GroupStore) AddGroupMemberTx(ctx context.Context, tx *sql.Tx, groupID, peerID int) (int64, error) {
	return addGroupMember(ctx, tx, groupID, peerID)
}

// DeleteGroupMemberTx deletes a group membership within a transaction so
// the pre-mutation snapshot and the delete commit atomically.
func (s *GroupStore) DeleteGroupMemberTx(ctx context.Context, tx *sql.Tx, groupID, peerID int) (bool, error) {
	return deleteGroupMember(ctx, tx, groupID, peerID)
}

func deleteGroupMember(ctx context.Context, q db.Querier, groupID, peerID int) (bool, error) {
	res, err := q.ExecContext(ctx, "DELETE FROM group_members WHERE group_id = ? AND peer_id = ?", groupID, peerID)
	if err != nil {
		return false, fmt.Errorf("delete member: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("delete member rows affected: %w", err)
	}
	return n > 0, nil
}

// Snapshot creates a snapshot of a group and its members.
func (s *GroupStore) Snapshot(ctx context.Context, action string, groupID int) error {
	if action == "create" {
		return db.CreateSnapshot(ctx, s.db, "group", groupID, action, "")
	}

	grp, err := s.GetGroupTx(ctx, s.db, groupID)
	if err != nil {
		// Normalize a concurrent delete (TOCTOU) to the sentinel so
		// handlers map it to 404 instead of 500 via sql.ErrNoRows.
		if errors.Is(err, sql.ErrNoRows) {
			return ErrGroupNotFound
		}
		return fmt.Errorf("get group: %w", err)
	}

	members, err := db.ListGroupMembers(ctx, s.db, groupID)
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

	return db.CreateSnapshot(ctx, s.db, "group", groupID, action, string(bytes))
}

// SnapshotTx creates a snapshot of a group and its members within a transaction.
func (s *GroupStore) SnapshotTx(ctx context.Context, tx *sql.Tx, action string, groupID int) error {
	if action == "create" {
		return db.CreateSnapshot(ctx, tx, "group", groupID, action, "")
	}

	grp, err := s.GetGroupTx(ctx, tx, groupID)
	if err != nil {
		// Normalize a concurrent delete (TOCTOU) to the sentinel so
		// handlers map it to 404 instead of 500 via sql.ErrNoRows.
		if errors.Is(err, sql.ErrNoRows) {
			return ErrGroupNotFound
		}
		return fmt.Errorf("get group: %w", err)
	}

	members, err := db.ListGroupMembers(ctx, tx, groupID)
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

	return db.CreateSnapshot(ctx, tx, "group", groupID, action, string(bytes))
}

// CheckDeleteConstraints checks whether a group can be safely deleted.
// It checks if the group is used as a source or target in any policy.
// Returns a *change.DeleteConstraintError with the full list of policies using the group.
func (s *GroupStore) CheckDeleteConstraints(ctx context.Context, groupID int) error {
	return s.CheckDeleteConstraintsTx(ctx, s.db, groupID)
}

// CheckDeleteConstraintsTx is the transactional variant of
// CheckDeleteConstraints. Delete handlers re-check constraints inside the
// snapshot+delete transaction so a policy created between the pre-check and
// the commit cannot leave a constrained group soft-deleted.
func (s *GroupStore) CheckDeleteConstraintsTx(ctx context.Context, q db.Querier, groupID int) error {
	// Query ALL policies that use the group (as source or target)
	policies, err := queryRows(ctx, q,
		`SELECT id, name FROM policies
		WHERE ((source_type='group' AND source_id=?) OR (target_type='group' AND target_id=?)) AND is_pending_delete = 0 ORDER BY id ASC`,
		[]any{groupID, groupID},
		"policy usage",
		func(rows *sql.Rows) (change.PolicyRef, error) {
			var p change.PolicyRef
			if err := rows.Scan(&p.ID, &p.Name); err != nil {
				return p, err
			}
			return p, nil
		},
	)
	if err != nil {
		return err
	}

	if len(policies) > 0 {
		return &change.DeleteConstraintError{
			Message:  "Cannot delete group: it is in use by policies",
			Policies: policies,
		}
	}

	return nil
}

// QueueGroupChange enqueues a group change notification via the ChangeWorker.
// Synchronous queue failures (nil worker, stopped/full fallback errors) are
// returned so handlers fail the request instead of acking success with a
// lost signal; nil means the change was accepted for background persistence.
func (s *GroupStore) QueueGroupChange(ctx context.Context, changeWorker *change.ChangeWorker, compiler *engine.Compiler, groupID int, changeAction string, summary string) error {
	if changeWorker == nil {
		log.WarnContext(ctx, "dropping group change: change worker is nil", "group_id", groupID, "change_action", changeAction)
		return fmt.Errorf("cannot queue group %d %s: change worker is nil", groupID, changeAction)
	}
	return changeWorker.QueueGroupChange(ctx, compiler, groupID, changeAction, summary)
}
