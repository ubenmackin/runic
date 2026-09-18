package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"runic/internal/change"
	ic "runic/internal/common"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/models"
)

const serviceRowColumns = `id, name, ports, COALESCE(source_ports, ''), protocol, COALESCE(description, ''), direction_hint, COALESCE(is_system, 0), COALESCE(no_conntrack, 0), COALESCE(is_pending_delete, 0)`

var ErrServiceNotFound = errors.New("service not found")

type ServiceStore struct {
	PeerChangeSupport
	db db.DB
}

func NewServiceStore(database db.DB) *ServiceStore {
	return &ServiceStore{db: database}
}

// GetNameByID returns the service name for a given ID. Returns sql.ErrNoRows if not found.
func (s *ServiceStore) GetNameByID(ctx context.Context, id int) (string, error) {
	return getNameByID(ctx, s.db, "services", id, "", "service")
}

// GetService returns a single non-deleted service by ID. Returns sql.ErrNoRows if not found.
func (s *ServiceStore) GetService(ctx context.Context, serviceID int) (models.ServiceRow, error) {
	var svc models.ServiceRow
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, ports, COALESCE(source_ports, ''), protocol, COALESCE(description, ''), direction_hint, COALESCE(is_system, 0)
		FROM services WHERE id = ? AND is_pending_delete = 0`, serviceID,
	).Scan(&svc.ID, &svc.Name, &svc.Ports, &svc.SourcePorts, &svc.Protocol, &svc.Description, &svc.DirectionHint, &svc.IsSystem)
	if err != nil {
		return models.ServiceRow{}, fmt.Errorf("get service: %w", err)
	}
	return svc, nil
}

// CheckDeleteConstraints checks whether a service can be safely deleted.
// It checks if the service is used in any policy (as service_id).
// Returns a *change.DeleteConstraintError with the full list of policies using the service.
func (s *ServiceStore) CheckDeleteConstraints(ctx context.Context, serviceID int) error {
	return s.CheckDeleteConstraintsTx(ctx, s.db, serviceID)
}

// CheckDeleteConstraintsTx is the transactional variant of
// CheckDeleteConstraints. Delete handlers re-check constraints inside the
// snapshot+delete transaction so a policy created between the pre-check and
// the commit cannot leave a constrained service soft-deleted.
func (s *ServiceStore) CheckDeleteConstraintsTx(ctx context.Context, q db.Querier, serviceID int) error {
	// Query ALL policies that use the service
	policies, err := queryRows(ctx, q,
		`SELECT id, name FROM policies WHERE service_id = ? AND is_pending_delete = 0 ORDER BY id ASC`,
		[]any{serviceID},
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
			Message:  "Cannot delete service: it is in use by policies",
			Policies: policies,
		}
	}

	return nil
}

func (s *ServiceStore) ListServices(ctx context.Context) ([]models.ServiceRow, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+serviceRowColumns+" FROM services WHERE is_pending_delete = 0 ORDER BY name ASC, id ASC")
	if err != nil {
		return nil, fmt.Errorf("query services: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.WarnContext(ctx, "failed to close rows", "error", cerr)
		}
	}()

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
	return ic.EnsureSlice(services), nil
}

func (s *ServiceStore) CreateService(ctx context.Context, name, ports, sourcePorts, protocol, description string, directionHint int, isSystem bool) (int64, error) {
	if name == "" {
		return 0, errors.New("service name is required")
	}
	if ports != "" {
		if err := validatePortList(ports); err != nil {
			return 0, fmt.Errorf("invalid ports: %w", err)
		}
	}
	if sourcePorts != "" {
		if err := validatePortList(sourcePorts); err != nil {
			return 0, fmt.Errorf("invalid source_ports: %w", err)
		}
	}
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

// validatePortList checks that each entry in a comma-separated port list is either a single port (1-65535)
// or a port range (e.g. "8000:9000"). Empty strings are allowed (caller should check non-empty before calling).
func validatePortList(portList string) error {
	for _, part := range strings.Split(portList, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return errors.New("empty port entry in list")
		}
		if strings.Contains(part, ":") {
			// Port range
			parts := strings.SplitN(part, ":", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid port range: %q", part)
			}
			lo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return fmt.Errorf("invalid port in range %q: %w", part, err)
			}
			hi, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return fmt.Errorf("invalid port in range %q: %w", part, err)
			}
			if lo < 1 || lo > 65535 || hi < 1 || hi > 65535 || lo > hi {
				return fmt.Errorf("port range out of bounds: %q", part)
			}
		} else {
			// Single port
			p, err := strconv.Atoi(part)
			if err != nil {
				return fmt.Errorf("invalid port: %q", part)
			}
			if p < 1 || p > 65535 {
				return fmt.Errorf("port out of range (1-65535): %d", p)
			}
		}
	}
	return nil
}

func (s *ServiceStore) UpdateService(ctx context.Context, id int, name, ports, sourcePorts, protocol, description string, directionHint int) error {
	return execUpdate(ctx, s.db,
		`UPDATE services SET name = ?, ports = ?, source_ports = ?, protocol = ?, description = ?, direction_hint = ?
		WHERE id = ? AND is_pending_delete = 0`, ErrServiceNotFound, name, ports, sourcePorts, protocol, description, directionHint, id)
}

func (s *ServiceStore) SoftDeleteService(ctx context.Context, id int) error {
	return softDelete(ctx, s.db, "services", id, ErrServiceNotFound)
}

func (s *ServiceStore) SoftDeleteServiceTx(ctx context.Context, tx *sql.Tx, id int) error {
	return softDelete(ctx, tx, "services", id, ErrServiceNotFound)
}

func (s *ServiceStore) GetServiceByPort(ctx context.Context, port, protocol string) ([]models.ServiceRow, error) {
	if port == "" || port == "0" {
		// Protocol-only lookup: search by protocol including system services
		query := "SELECT " + serviceRowColumns + " FROM services WHERE (protocol = ? OR protocol = 'both') AND is_pending_delete = 0 LIMIT 1"

		var svc models.ServiceRow
		err := s.db.QueryRowContext(ctx, query, protocol).Scan(
			&svc.ID, &svc.Name, &svc.Ports, &svc.SourcePorts, &svc.Protocol, &svc.Description, &svc.DirectionHint, &svc.IsSystem, &svc.NoConntrack, &svc.IsPendingDelete)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ic.EnsureSlice([]models.ServiceRow{}), nil
			}
			return nil, fmt.Errorf("get service by port: %w", err)
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
		if errors.Is(err, sql.ErrNoRows) {
			return ic.EnsureSlice([]models.ServiceRow{}), nil
		}
		return nil, fmt.Errorf("get service by port: %w", err)
	}
	return []models.ServiceRow{svc}, nil
}

// SnapshotService creates a snapshot of a service.
func (s *ServiceStore) SnapshotService(ctx context.Context, serviceID int, action string) error {
	if action == "create" {
		return db.CreateSnapshot(ctx, s.db, "service", serviceID, action, "")
	}

	svc, err := db.GetService(ctx, s.db, serviceID)
	if err != nil {
		// Normalize a concurrent delete (TOCTOU) to the sentinel so
		// handlers map it to 404 instead of 500 via sql.ErrNoRows.
		if errors.Is(err, sql.ErrNoRows) {
			return ErrServiceNotFound
		}
		return fmt.Errorf("get service: %w", err)
	}

	bytes, err := json.Marshal(svc)
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	return db.CreateSnapshot(ctx, s.db, "service", serviceID, action, string(bytes))
}

// SnapshotServiceTx creates a snapshot of a service within a transaction.
func (s *ServiceStore) SnapshotServiceTx(ctx context.Context, tx *sql.Tx, serviceID int, action string) error {
	if action == "create" {
		return db.CreateSnapshot(ctx, tx, "service", serviceID, action, "")
	}

	svc, err := db.GetService(ctx, tx, serviceID)
	if err != nil {
		// Normalize a concurrent delete (TOCTOU) to the sentinel so
		// handlers map it to 404 instead of 500 via sql.ErrNoRows.
		if errors.Is(err, sql.ErrNoRows) {
			return ErrServiceNotFound
		}
		return fmt.Errorf("get service: %w", err)
	}

	bytes, err := json.Marshal(svc)
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	return db.CreateSnapshot(ctx, tx, "service", serviceID, action, string(bytes))
}

// UpdateServiceTx updates a service within a transaction.
func (s *ServiceStore) UpdateServiceTx(ctx context.Context, tx *sql.Tx, id int, name, ports, sourcePorts, protocol, description string, directionHint int) error {
	return execUpdate(ctx, tx,
		`UPDATE services SET name = ?, ports = ?, source_ports = ?, protocol = ?, description = ?, direction_hint = ?
		WHERE id = ? AND is_pending_delete = 0`, ErrServiceNotFound, name, ports, sourcePorts, protocol, description, directionHint, id)
}

func (s *ServiceStore) FindPoliciesUsingService(ctx context.Context, serviceID int) ([]int, error) {
	// Single shared helper for service fan-out (also used by the importer
	// and the services handler path): the SELECT WHERE service_id=? AND
	// is_pending_delete=0 predicate lives in db.FindPolicyIDsByService so
	// the three call sites cannot diverge.
	ids, err := db.FindPolicyIDsByService(ctx, s.db, serviceID)
	if err != nil {
		return nil, err
	}
	return ic.EnsureSlice(ids), nil
}
