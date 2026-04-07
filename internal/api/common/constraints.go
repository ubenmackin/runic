// Package common provides shared utilities and constants.
package common

import (
	"context"
	"fmt"

	"runic/internal/db"
)

// PolicyRef represents a reference to a policy for constraint error responses.
type PolicyRef struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// DeleteConstraintError is returned when attempting to delete an entity
// that is in use by one or more policies.
type DeleteConstraintError struct {
	Message  string      `json:"error"`
	Policies []PolicyRef `json:"policies"`
}

// Error implements the error interface.
func (e *DeleteConstraintError) Error() string {
	return e.Message
}

// ToResponse converts the error to a JSON-friendly response map.
func (e *DeleteConstraintError) ToResponse() map[string]interface{} {
	return map[string]interface{}{
		"error":    e.Message,
		"policies": e.Policies,
	}
}

// CheckPeerDeleteConstraints returns an error if the peer is in use by any policy.
// It checks:
// 1. If the peer is explicitly a target_id (and type='peer') or source_id (and type='peer')
// 2. If the peer is in a group that is used by a policy
// Returns a DeleteConstraintError containing all policies that reference the peer.
func CheckPeerDeleteConstraints(ctx context.Context, database db.Querier, peerID int) error {
	var policies []PolicyRef

	// Check 1: Explicit Peer Policy (peer as source or target)
	rows, err := database.QueryContext(ctx,
		`SELECT id, name FROM policies
		WHERE (target_type='peer' AND target_id=?) OR (source_type='peer' AND source_id=?)`,
		peerID, peerID,
	)
	if err != nil {
		return fmt.Errorf("failed to query peer policies: %w", err)
	}
	for rows.Next() {
		var ref PolicyRef
		if scanErr := rows.Scan(&ref.ID, &ref.Name); scanErr == nil {
			policies = append(policies, ref)
		}
	}
	if closeErr := rows.Close(); closeErr != nil {
		return fmt.Errorf("failed to close rows: %w", closeErr)
	}

	// Check 2: Group Policy (peer is in a group used by policy)
	rows, err = database.QueryContext(ctx, `
		SELECT DISTINCT p.id, p.name FROM policies p
		JOIN group_members gm ON (gm.group_id = p.source_id AND p.source_type='group') OR (gm.group_id = p.target_id AND p.target_type='group')
		WHERE gm.peer_id = ?
	`, peerID)
	if err != nil {
		return fmt.Errorf("failed to query group policies: %w", err)
	}
	for rows.Next() {
		var ref PolicyRef
		if scanErr := rows.Scan(&ref.ID, &ref.Name); scanErr == nil {
			policies = append(policies, ref)
		}
	}
	if closeErr := rows.Close(); closeErr != nil {
		return fmt.Errorf("failed to close rows: %w", closeErr)
	}

	if len(policies) > 0 {
		return &DeleteConstraintError{
			Message:  "cannot delete peer — it is in use by one or more policies",
			Policies: policies,
		}
	}

	return nil
}

// CheckGroupDeleteConstraints returns an error if the group is in use by any policy.
// It checks if the group is used as a source or target in any policy.
// Returns a DeleteConstraintError with the full list of policies using the group.
func CheckGroupDeleteConstraints(ctx context.Context, database db.Querier, groupID int) error {
	// Query ALL policies that use the group (as source or target)
	rows, err := database.QueryContext(ctx,
		`SELECT id, name FROM policies
		WHERE (source_type='group' AND source_id=?) OR (target_type='group' AND target_id=?)`,
		groupID, groupID,
	)
	if err != nil {
		return fmt.Errorf("failed to check policy usage: %w", err)
	}

	var policies []PolicyRef
	for rows.Next() {
		var p PolicyRef
		if err := rows.Scan(&p.ID, &p.Name); err != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return fmt.Errorf("failed to scan policy: %v, close error: %w", err, closeErr)
			}
			return fmt.Errorf("failed to scan policy: %w", err)
		}
		policies = append(policies, p)
	}
	if closeErr := rows.Close(); closeErr != nil {
		return fmt.Errorf("failed to close rows: %w", closeErr)
	}

	if len(policies) > 0 {
		return &DeleteConstraintError{
			Message:  "Cannot delete group: it is in use by policies",
			Policies: policies,
		}
	}

	return nil
}
