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

const serviceRowColumns = `id, name, ports, COALESCE(source_ports, ''), protocol, COALESCE(description, ''), direction_hint, COALESCE(is_system, 0), COALESCE(no_conntrack, 0), COALESCE(is_pending_delete, 0)`

type ServiceStore struct {
	db db.Querier
}

func NewServiceStore(database db.Querier) *ServiceStore {
	return &ServiceStore{db: database}
}

// DB returns the underlying db.Querier for use with functions that require direct database access.
func (s *ServiceStore) DB() db.Querier {
	return s.db
}

func (s *ServiceStore) ListServices(ctx context.Context) ([]models.ServiceRow, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+serviceRowColumns+" FROM services")
	if err != nil {
		return nil, fmt.Errorf("query services: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var services []models.ServiceRow
	for rows.Next() {
		var svc models.ServiceRow
		if err := rows.Scan(&svc.ID, &svc.Name, &svc.Ports, &svc.SourcePorts, &svc.Protocol, &svc.Description, &svc.DirectionHint, &svc.IsSystem, &svc.NoConntrack, &svc.IsPendingDelete); err != nil {
			return nil, fmt.Errorf("scan service: %w", err)
		}
		services = append(services, svc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return common.EnsureSlice(services), nil
}

func (s *ServiceStore) CreateService(ctx context.Context, name, ports, sourcePorts, protocol, description string, directionHint int, isSystem bool) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO services (name, ports, source_ports, protocol, description, direction_hint, is_system)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, name, ports, sourcePorts, protocol, description, directionHint, isSystem)
	if err != nil {
		return 0, fmt.Errorf("insert service: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get insert id: %w", err)
	}
	return id, nil
}

func (s *ServiceStore) UpdateService(ctx context.Context, id int, name, ports, sourcePorts, protocol, description string, directionHint int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE services SET name = ?, ports = ?, source_ports = ?, protocol = ?, description = ?, direction_hint = ?
		WHERE id = ?`, name, ports, sourcePorts, protocol, description, directionHint, id)
	if err != nil {
		return fmt.Errorf("update service: %w", err)
	}
	return nil
}

func (s *ServiceStore) SoftDeleteService(ctx context.Context, id int) error {
	res, err := s.db.ExecContext(ctx, "UPDATE services SET is_pending_delete = 1 WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("soft delete service: %w", err)
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

func (s *ServiceStore) GetServiceByPort(ctx context.Context, port, protocol string) ([]models.ServiceRow, error) {
	if port == "" || port == "0" {
		// Protocol-only lookup: search by protocol including system services
		query := "SELECT " + serviceRowColumns + " FROM services WHERE (protocol = ? OR protocol = 'both') AND is_pending_delete = 0 LIMIT 1"

		var svc models.ServiceRow
		err := s.db.QueryRowContext(ctx, query, protocol).Scan(
			&svc.ID, &svc.Name, &svc.Ports, &svc.SourcePorts, &svc.Protocol, &svc.Description, &svc.DirectionHint, &svc.IsSystem, &svc.NoConntrack, &svc.IsPendingDelete)
		if err != nil {
			return common.EnsureSlice([]models.ServiceRow{}), nil
		}
		return []models.ServiceRow{svc}, nil
	}

	// Port + optional protocol lookup
	query := "SELECT " + serviceRowColumns + " FROM services WHERE (ports = ? OR ports LIKE ? OR ports LIKE ? OR ports LIKE ?) AND is_system = 0 AND is_pending_delete = 0"
	args := []interface{}{port, port + ",%", "%," + port + ",%", "%," + port}

	if protocol != "" {
		query += " AND (protocol = ? OR protocol = 'both')"
		args = append(args, protocol)
	}

	query += " LIMIT 1"

	var svc models.ServiceRow
	err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&svc.ID, &svc.Name, &svc.Ports, &svc.SourcePorts, &svc.Protocol, &svc.Description, &svc.DirectionHint, &svc.IsSystem, &svc.NoConntrack, &svc.IsPendingDelete)
	if err != nil {
		return common.EnsureSlice([]models.ServiceRow{}), nil
	}
	return []models.ServiceRow{svc}, nil
}

// SnapshotService creates a snapshot of a service for change tracking.
// The q parameter allows it to be used inside or outside a transaction.
func (s *ServiceStore) SnapshotService(ctx context.Context, q db.Querier, serviceID int, action string) error {
	if action == "create" {
		return db.CreateSnapshot(ctx, q, "service", serviceID, action, "")
	}

	svc, err := db.GetService(ctx, q, serviceID)
	if err != nil {
		return fmt.Errorf("get service: %w", err)
	}

	bytes, err := json.Marshal(svc)
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	return db.CreateSnapshot(ctx, q, "service", serviceID, action, string(bytes))
}

func (s *ServiceStore) FindPoliciesUsingService(ctx context.Context, serviceID int) ([]int, error) {
	rows, err := s.db.QueryContext(ctx, `
	SELECT DISTINCT id FROM policies
	WHERE service_id = ? AND enabled = 1
	`, serviceID)
	if err != nil {
		return nil, fmt.Errorf("query policies for service: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var policyIDs []int
	for rows.Next() {
		var policyID int
		if err := rows.Scan(&policyID); err != nil {
			return nil, fmt.Errorf("scan policy id: %w", err)
		}
		policyIDs = append(policyIDs, policyID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return common.EnsureSlice(policyIDs), nil
}
