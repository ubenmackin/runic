// Package services provides service handlers.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"runic/internal/api/common"
	ic "runic/internal/common"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
)

// Handler holds dependencies for service handlers.
type Handler struct {
	DB           db.Querier
	Compiler     *engine.Compiler
	ChangeWorker *common.ChangeWorker
}

// NewHandler creates a new services handler with dependencies.
func NewHandler(db db.Querier, compiler *engine.Compiler, changeWorker *common.ChangeWorker) *Handler {
	return &Handler{DB: db, Compiler: compiler, ChangeWorker: changeWorker}
}

// validProtocols is the set of allowed protocol values for user-defined services.
// Note: ICMP and IGMP are only allowed for system services, not user-defined services.
var validProtocols = map[string]bool{
	"tcp":  true,
	"udp":  true,
	"both": true,
}

// validLookupProtocols is the set of allowed protocol values for the
// protocol-only lookup path in GetServiceByPort. This includes system-only
// protocols (icmp, igmp) since the protocol-only path searches system services.
var validLookupProtocols = map[string]bool{
	"tcp":  true,
	"udp":  true,
	"both": true,
	"icmp": true,
	"igmp": true,
}

// validateService checks that ports, source_ports, and protocol are safe to compile into iptables rules.
// For user-defined services, ICMP and IGMP protocols are blocked.
// For non-ICMP/IGMP protocols, at least one of ports or source_ports is required.
func validateService(ports, sourcePorts, protocol string, isSystem bool) error {
	if protocol == "icmp" && !isSystem {
		return fmt.Errorf("ICMP protocol is reserved for system services and cannot be used for user-defined services")
	}
	if protocol == "igmp" && !isSystem {
		return fmt.Errorf("IGMP protocol is reserved for system services and cannot be used for user-defined services")
	}

	if protocol != "icmp" && protocol != "igmp" && !validProtocols[protocol] {
		return fmt.Errorf("invalid protocol %q: must be tcp, udp, or both", protocol)
	}

	if protocol == "icmp" || protocol == "igmp" {
		return nil
	}

	if ports == "" && sourcePorts == "" {
		return fmt.Errorf("at least one port type (destination ports or source ports) is required for protocol %q", protocol)
	}

	if ports != "" && !engine.ValidPortsRe.MatchString(ports) {
		return fmt.Errorf("invalid destination ports %q: must be digits separated by commas or colons", ports)
	}

	if sourcePorts != "" && !engine.ValidPortsRe.MatchString(sourcePorts) {
		return fmt.Errorf("invalid source ports %q: must be digits separated by commas or colons", sourcePorts)
	}

	return nil
}

// --- Services ---

func (h *Handler) ListServices(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		"SELECT id, name, ports, COALESCE(source_ports, ''), protocol, COALESCE(description, ''), direction_hint, COALESCE(is_system, 0), COALESCE(is_pending_delete, 0) FROM services")
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query services")
		return
	}
	defer func() {
		if cErr := rows.Close(); cErr != nil {
			log.Warn("Failed to close rows", "error", cErr)
		}
	}()

	type serviceResp struct {
		ID              int    `json:"id"`
		Name            string `json:"name"`
		Ports           string `json:"ports"`
		SourcePorts     string `json:"source_ports"`
		Protocol        string `json:"protocol"`
		Description     string `json:"description"`
		DirectionHint   string `json:"direction_hint"`
		IsSystem        bool   `json:"is_system"`
		IsPendingDelete bool   `json:"is_pending_delete"`
	}

	var servicesData []serviceResp
	for rows.Next() {
		var s serviceResp
		if err := rows.Scan(&s.ID, &s.Name, &s.Ports, &s.SourcePorts, &s.Protocol, &s.Description, &s.DirectionHint, &s.IsSystem, &s.IsPendingDelete); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to scan service")
			return
		}
		servicesData = append(servicesData, s)
	}
	servicesData = ic.EnsureSlice(servicesData)
	common.RespondJSON(w, http.StatusOK, servicesData)
}

func (h *Handler) CreateService(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name          string `json:"name"`
		Ports         string `json:"ports"`
		SourcePorts   string `json:"source_ports"`
		Protocol      string `json:"protocol"`
		Description   string `json:"description"`
		DirectionHint string `json:"direction_hint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate name
	if input.Name != "" {
		if err := common.ValidateName(input.Name); err != nil {
			common.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if input.Name == "" {
		common.RespondError(w, http.StatusBadRequest, "name is required")
		return
	}
	if input.Protocol == "" {
		input.Protocol = "tcp"
	}
	if input.DirectionHint == "" {
		input.DirectionHint = "inbound"
	}

	if err := validateService(input.Ports, input.SourcePorts, input.Protocol, false); err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	result, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO services (name, ports, source_ports, protocol, description, direction_hint, is_system)
		VALUES (?, ?, ?, ?, ?, ?, 0)`, input.Name, input.Ports, input.SourcePorts, input.Protocol, input.Description, input.DirectionHint)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to create service", "error", err)
		common.InternalError(w)
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		log.ErrorContext(r.Context(), "failed to get insert ID", "error", err)
		common.InternalError(w)
		return
	}

	if err := h.snapshotService(r.Context(), "create", int(id)); err != nil {
		log.ErrorContext(r.Context(), "failed to create snapshot", "error", err)
	}
	h.queueServiceChange(r.Context(), int(id), "create", fmt.Sprintf("Service '%s' created", input.Name))

	common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (h *Handler) GetService(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid service ID")
		return
	}

	s, err := db.GetService(r.Context(), h.DB, id)
	if err != nil {
		common.RespondError(w, http.StatusNotFound, "service not found")
		return
	}

	common.RespondJSON(w, http.StatusOK, s)
}

func (h *Handler) UpdateService(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid service ID")
		return
	}

	// Check if this is a system service
	var isSystem bool
	err = h.DB.QueryRowContext(r.Context(), "SELECT COALESCE(is_system, 0) FROM services WHERE id = ?", id).Scan(&isSystem)
	if err != nil {
		common.RespondError(w, http.StatusNotFound, "service not found")
		return
	}

	if isSystem {
		common.RespondError(w, http.StatusForbidden, "Cannot edit system service")
		return
	}

	var input struct {
		Name          string `json:"name"`
		Ports         string `json:"ports"`
		SourcePorts   string `json:"source_ports"`
		Protocol      string `json:"protocol"`
		Description   string `json:"description"`
		DirectionHint string `json:"direction_hint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate name
	if input.Name != "" {
		if err := common.ValidateName(input.Name); err != nil {
			common.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if input.Protocol == "" {
		input.Protocol = "tcp"
	}

	if err := validateService(input.Ports, input.SourcePorts, input.Protocol, isSystem); err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.snapshotService(r.Context(), "update", id); err != nil {
		log.ErrorContext(r.Context(), "failed to create snapshot", "error", err)
	}

	_, err = h.DB.ExecContext(r.Context(),
		`UPDATE services SET name = ?, ports = ?, source_ports = ?, protocol = ?, description = ?, direction_hint = ?
		WHERE id = ?`, input.Name, input.Ports, input.SourcePorts, input.Protocol, input.Description, input.DirectionHint, id)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to update service", "error", err)
		common.InternalError(w)
		return
	}

	h.queueServiceChange(r.Context(), id, "update", fmt.Sprintf("Service '%s' updated", input.Name))

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) DeleteService(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid service ID")
		return
	}

	var serviceName string
	err = h.DB.QueryRowContext(r.Context(), "SELECT name FROM services WHERE id = ?", id).Scan(&serviceName)
	if err != nil {
		common.RespondError(w, http.StatusNotFound, "service not found")
		return
	}

	// Check if this is a system service
	var isSystem bool
	err = h.DB.QueryRowContext(r.Context(), "SELECT COALESCE(is_system, 0) FROM services WHERE id = ?", id).Scan(&isSystem)
	if err != nil {
		common.RespondError(w, http.StatusNotFound, "service not found")
		return
	}

	if isSystem {
		common.RespondError(w, http.StatusForbidden, "Cannot delete system service")
		return
	}

	err = common.CheckServiceDeleteConstraints(r.Context(), h.DB, id)
	if err != nil {
		constraintErr, ok := err.(*common.DeleteConstraintError)
		if ok {
			common.RespondJSON(w, http.StatusConflict, constraintErr.ToResponse())
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to check constraints")
		return
	}

	if err := h.snapshotService(r.Context(), "delete", id); err != nil {
		log.ErrorContext(r.Context(), "failed to create snapshot", "error", err)
	}

	_, err = h.DB.ExecContext(r.Context(), "UPDATE services SET is_pending_delete = 1 WHERE id = ?", id)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to delete service", "error", err)
		common.InternalError(w)
		return
	}

	h.queueServiceChange(r.Context(), id, "delete", fmt.Sprintf("Service '%s' deleted", serviceName))

	w.WriteHeader(http.StatusNoContent)
}

// queueServiceChange queues pending changes for all peers affected by policies using this service.
func (h *Handler) queueServiceChange(ctx context.Context, serviceID int, action, summary string) {
	rows, err := h.DB.QueryContext(ctx, `
		SELECT DISTINCT id FROM policies
		WHERE service_id = ? AND enabled = 1
	`, serviceID)
	if err != nil {
		log.ErrorContext(ctx, "failed to find policies for service", "service_id", serviceID, "error", err)
		return
	}
	defer func() {
		if cErr := rows.Close(); cErr != nil {
			log.Warn("Failed to close rows", "error", cErr)
		}
	}()

	peerSet := make(map[int]bool)
	for rows.Next() {
		var policyID int
		if err := rows.Scan(&policyID); err != nil {
			continue
		}
		affectedPeers, err := h.Compiler.GetAffectedPeersByPolicy(ctx, policyID)
		if err != nil {
			log.ErrorContext(ctx, "Failed to get affected peers for service change", "policy_id", policyID, "error", err)
			continue
		}
		for _, peerID := range affectedPeers {
			peerSet[peerID] = true
		}
	}

	if err := rows.Err(); err != nil {
		log.ErrorContext(ctx, "failed to iterate policies for service", "service_id", serviceID, "error", err)
		return
	}

	peerIDs := make([]int, 0, len(peerSet))
	for peerID := range peerSet {
		peerIDs = append(peerIDs, peerID)
	}

	if len(peerIDs) > 0 && h.ChangeWorker != nil {
		h.ChangeWorker.QueuePeerChange(ctx, h.DB, peerIDs, "service", action, serviceID, summary)
	}
}

func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("", h.ListServices).Methods("GET")
	r.HandleFunc("", h.CreateService).Methods("POST")
	r.HandleFunc("/by-port", h.GetServiceByPort).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.GetService).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.UpdateService).Methods("PUT")
	r.HandleFunc("/{id:[0-9]+}", h.DeleteService).Methods("DELETE")
}

// GetServiceByPort returns the first user service matching a given port and optional protocol.
// When port is "0" or empty and protocol is provided, it performs a protocol-only lookup
// that includes system services (useful for ICMP/IGMP which have no ports).
// GET /api/v1/services/by-port?port=<port>&protocol=<protocol>
func (h *Handler) GetServiceByPort(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("port")
	protocol := r.URL.Query().Get("protocol")

	type serviceResp struct {
		ID              int    `json:"id"`
		Name            string `json:"name"`
		Ports           string `json:"ports"`
		SourcePorts     string `json:"source_ports"`
		Protocol        string `json:"protocol"`
		Description     string `json:"description"`
		DirectionHint   string `json:"direction_hint"`
		IsSystem        bool   `json:"is_system"`
		IsPendingDelete bool   `json:"is_pending_delete"`
	}

	if port == "" || port == "0" {
		if protocol == "" {
			common.RespondError(w, http.StatusBadRequest, "port or protocol parameter required")
			return
		}

		// Validate protocol value for protocol-only lookup
		if !validLookupProtocols[protocol] {
			common.RespondError(w, http.StatusBadRequest, "invalid protocol")
			return
		}

		// Protocol-only lookup: search by protocol including system services
		// Match both the exact protocol and 'both' (which applies to tcp and udp)
		query := `
		SELECT id, name, ports, COALESCE(source_ports, ''), protocol, COALESCE(description, ''), direction_hint, COALESCE(is_system, 0), COALESCE(is_pending_delete, 0)
		FROM services
		WHERE (protocol = ? OR protocol = 'both') AND is_pending_delete = 0
		LIMIT 1
		`

		var s serviceResp
		err := h.DB.QueryRowContext(r.Context(), query, protocol).Scan(
			&s.ID, &s.Name, &s.Ports, &s.SourcePorts, &s.Protocol, &s.Description, &s.DirectionHint, &s.IsSystem, &s.IsPendingDelete)
		if err != nil {
			// No match found - return null
			common.RespondJSON(w, http.StatusOK, nil)
			return
		}

		common.RespondJSON(w, http.StatusOK, s)
		return
	}

	// Validate port format
	if !engine.ValidPortsRe.MatchString(port) {
		common.RespondError(w, http.StatusBadRequest, "invalid port format")
		return
	}

	// Build query to find service where port is in the ports list
	// The ports field is comma-separated, so we need to match:
	// - port exactly (e.g., "80")
	// - port at start of list (e.g., "80,443")
	// - port in middle of list (e.g., "443,80,8080")
	// - port at end of list (e.g., "443,80")
	query := `
	SELECT id, name, ports, COALESCE(source_ports, ''), protocol, COALESCE(description, ''), direction_hint, COALESCE(is_system, 0), COALESCE(is_pending_delete, 0)
	FROM services
	WHERE (ports = ? OR ports LIKE ? OR ports LIKE ? OR ports LIKE ?)
	AND is_system = 0
	AND is_pending_delete = 0
	`
	args := []interface{}{port, port + ",%", "%," + port + ",%", "%," + port}

	if protocol != "" {
		query += " AND (protocol = ? OR protocol = 'both')"
		args = append(args, protocol)
	}

	query += " LIMIT 1"

	var s serviceResp
	err := h.DB.QueryRowContext(r.Context(), query, args...).Scan(
		&s.ID, &s.Name, &s.Ports, &s.SourcePorts, &s.Protocol, &s.Description, &s.DirectionHint, &s.IsSystem, &s.IsPendingDelete)
	if err != nil {
		// No match found - return null
		common.RespondJSON(w, http.StatusOK, nil)
		return
	}

	common.RespondJSON(w, http.StatusOK, s)
}

func (h *Handler) snapshotService(ctx context.Context, action string, serviceID int) error {
	if action == "create" {
		return db.CreateSnapshot(ctx, h.DB, "service", serviceID, action, "")
	}

	svc, err := db.GetService(ctx, h.DB, serviceID)
	if err != nil {
		return fmt.Errorf("get service: %w", err)
	}

	bytes, err := json.Marshal(svc)
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	return db.CreateSnapshot(ctx, h.DB, "service", serviceID, action, string(bytes))
}
