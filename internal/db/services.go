package db

import (
	"context"

	"runic/internal/models"
)

// GetService fetches a service by ID.
func GetService(ctx context.Context, database Querier, serviceID int) (models.ServiceRow, error) {
	var s models.ServiceRow
	err := database.QueryRowContext(ctx,
		`SELECT id, name, ports, COALESCE(source_ports, ''), protocol, COALESCE(description, ''), direction_hint, COALESCE(is_system, 0)
		FROM services WHERE id = ? AND COALESCE(is_pending_delete, 0) = 0`, serviceID,
	).Scan(&s.ID, &s.Name, &s.Ports, &s.SourcePorts, &s.Protocol, &s.Description, &s.DirectionHint, &s.IsSystem)
	return s, err
}
