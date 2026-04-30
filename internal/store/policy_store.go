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

type PolicyStore struct {
	db db.Querier
}

func NewPolicyStore(database db.Querier) *PolicyStore {
	return &PolicyStore{db: database}
}

// nullableIP converts a scanned IP string into a nil pointer when empty,
// matching the nullable semantics of the database column.
func nullableIP(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (s *PolicyStore) ListPolicies(ctx context.Context) ([]models.PolicyRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, COALESCE(description, ''), source_id, source_type, service_id,
		target_id, target_type, COALESCE(source_ip, ''), COALESCE(target_ip, ''), action, priority, enabled, target_scope, COALESCE(direction, 'both'), created_at, updated_at, is_pending_delete
		FROM policies ORDER BY priority ASC`)
	if err != nil {
		return nil, fmt.Errorf("query policies: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var policies []models.PolicyRow
	for rows.Next() {
		var p models.PolicyRow
		var sourceIPStr, targetIPStr string
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.SourceID, &p.SourceType, &p.ServiceID,
			&p.TargetID, &p.TargetType, &sourceIPStr, &targetIPStr, &p.Action, &p.Priority, &p.Enabled, &p.TargetScope, &p.Direction, &p.CreatedAt, &p.UpdatedAt, &p.IsPendingDelete); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		p.SourceIP = nullableIP(sourceIPStr)
		p.TargetIP = nullableIP(targetIPStr)
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return common.EnsureSlice(policies), nil
}

func (s *PolicyStore) CreatePolicy(ctx context.Context, p *models.PolicyRow) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO policies (name, description, source_id, source_type, service_id, target_id, target_type, source_ip, target_ip, action, priority, enabled, target_scope, direction)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Description, p.SourceID, p.SourceType, p.ServiceID,
		p.TargetID, p.TargetType, p.SourceIP, p.TargetIP, p.Action, p.Priority, p.Enabled, p.TargetScope, p.Direction)
	if err != nil {
		return 0, fmt.Errorf("insert policy: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get insert id: %w", err)
	}
	return id, nil
}

func (s *PolicyStore) GetPolicy(ctx context.Context, id int) (models.PolicyRow, error) {
	return s.GetPolicyTx(ctx, s.db, id)
}

func (s *PolicyStore) GetPolicyTx(ctx context.Context, q db.Querier, id int) (models.PolicyRow, error) {
	var p models.PolicyRow
	var sourceIPStr, targetIPStr string
	err := q.QueryRowContext(ctx,
		`SELECT id, name, COALESCE(description, ''), source_id, source_type, service_id,
		target_id, target_type, COALESCE(source_ip, ''), COALESCE(target_ip, ''), action, priority, enabled, target_scope, COALESCE(direction, 'both'), created_at, updated_at, is_pending_delete
		FROM policies WHERE id = ? AND is_pending_delete = 0`, id,
	).Scan(&p.ID, &p.Name, &p.Description, &p.SourceID, &p.SourceType, &p.ServiceID,
		&p.TargetID, &p.TargetType, &sourceIPStr, &targetIPStr, &p.Action, &p.Priority, &p.Enabled, &p.TargetScope, &p.Direction, &p.CreatedAt, &p.UpdatedAt, &p.IsPendingDelete)
	if err != nil {
		return p, fmt.Errorf("query policy: %w", err)
	}
	p.SourceIP = nullableIP(sourceIPStr)
	p.TargetIP = nullableIP(targetIPStr)
	return p, nil
}

func (s *PolicyStore) GetPolicyName(ctx context.Context, id int) (string, error) {
	var name string
	err := s.db.QueryRowContext(ctx, "SELECT name FROM policies WHERE id = ? AND is_pending_delete = 0", id).Scan(&name)
	if err != nil {
		return "", fmt.Errorf("query policy name: %w", err)
	}
	return name, nil
}

func (s *PolicyStore) UpdatePolicy(ctx context.Context, q db.Querier, p *models.PolicyRow) error {
	result, err := q.ExecContext(ctx,
		`UPDATE policies SET name = ?, description = ?, source_id = ?, source_type = ?, service_id = ?,
		target_id = ?, target_type = ?, source_ip = ?, target_ip = ?, action = ?, priority = ?, enabled = ?, target_scope = ?, direction = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND is_pending_delete = 0`,
		p.Name, p.Description, p.SourceID, p.SourceType, p.ServiceID,
		p.TargetID, p.TargetType, p.SourceIP, p.TargetIP, p.Action, p.Priority, p.Enabled, p.TargetScope, p.Direction, p.ID)
	if err != nil {
		return fmt.Errorf("update policy: %w", err)
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

func (s *PolicyStore) PatchPolicyEnabled(ctx context.Context, q db.Querier, id int, enabled bool) error {
	result, err := q.ExecContext(ctx, "UPDATE policies SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND is_pending_delete = 0", enabled, id)
	if err != nil {
		return fmt.Errorf("patch policy: %w", err)
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

func (s *PolicyStore) SoftDeletePolicy(ctx context.Context, q db.Querier, id int) error {
	res, err := q.ExecContext(ctx, "UPDATE policies SET is_pending_delete = 1 WHERE id = ? AND is_pending_delete = 0", id)
	if err != nil {
		return fmt.Errorf("soft delete policy: %w", err)
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

func (s *PolicyStore) Snapshot(ctx context.Context, q db.Querier, action string, policyID int) error {
	if action == "create" {
		return db.CreateSnapshot(ctx, q, "policy", policyID, action, "")
	}

	p, err := s.GetPolicyTx(ctx, q, policyID)
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}

	bytes, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	return db.CreateSnapshot(ctx, q, "policy", policyID, action, string(bytes))
}

func (s *PolicyStore) ListSpecialTargets(ctx context.Context) ([]models.SpecialTargetRow, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, name, display_name, COALESCE(description, ''), address FROM special_targets ORDER BY id ASC")
	if err != nil {
		return nil, fmt.Errorf("query special targets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var targets []models.SpecialTargetRow
	for rows.Next() {
		var t models.SpecialTargetRow
		if err := rows.Scan(&t.ID, &t.Name, &t.DisplayName, &t.Description, &t.Address); err != nil {
			return nil, fmt.Errorf("scan special target: %w", err)
		}
		targets = append(targets, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return common.EnsureSlice(targets), nil
}
