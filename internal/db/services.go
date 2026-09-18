package db

import (
	"context"
	"fmt"

	"runic/internal/common/log"
	"runic/internal/models"
)

func GetService(ctx context.Context, database Querier, serviceID int) (models.ServiceRow, error) {
	var s models.ServiceRow
	err := database.QueryRowContext(ctx,
		`SELECT id, name, ports, COALESCE(source_ports, ''), protocol, COALESCE(description, ''), direction_hint, COALESCE(is_system, 0)
		FROM services WHERE id = ? AND is_pending_delete = 0`, serviceID,
	).Scan(&s.ID, &s.Name, &s.Ports, &s.SourcePorts, &s.Protocol, &s.Description, &s.DirectionHint, &s.IsSystem)
	return s, err
}

// FindPolicyIDsByService returns IDs of non-deleted policies that use the
// given service. It is the single shared helper for service fan-out so the
// SELECT WHERE service_id=? AND is_pending_delete=0 predicate lives in
// exactly one place.
//
// Conservative superset: intentionally includes disabled policies,
// mirroring engine.GetAffectedPeersByPolicy which ignores the enabled
// flag so disable fan-out still resolves the previously-affected peers.
// Over-marking (an extra pending signal) is safe; under-marking a
// service edit that touches a disabled policy would lose the pending
// signal with zero fan-out. Soft-deleted policies are excluded via
// is_pending_delete=0.
func FindPolicyIDsByService(ctx context.Context, database Querier, serviceID int) ([]int, error) {
	rows, err := database.QueryContext(ctx, `
	SELECT DISTINCT id FROM policies
	WHERE service_id = ? AND is_pending_delete = 0
	ORDER BY id ASC
	`, serviceID)
	if err != nil {
		return nil, fmt.Errorf("query policies for service %d: %w", serviceID, err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.WarnContext(ctx, "failed to close rows", "error", cerr)
		}
	}()
	ids := make([]int, 0)
	for rows.Next() {
		var policyID int
		if err := rows.Scan(&policyID); err != nil {
			return nil, fmt.Errorf("scan policy for service %d: %w", serviceID, err)
		}
		ids = append(ids, policyID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policies for service %d: %w", serviceID, err)
	}
	return ids, nil
}
