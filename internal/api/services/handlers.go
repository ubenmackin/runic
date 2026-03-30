package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"runic/internal/api/common"
	"runic/internal/db"
)

// validPortsRe matches comma/colon-separated port numbers (e.g. "22", "80,443", "8000:9000").
var validPortsRe = regexp.MustCompile(`^\d+([,:]\d+)*$`)

// validProtocols is the set of allowed protocol values for user-defined services.
// Note: ICMP and IGMP are only allowed for system services, not user-defined services.
var validProtocols = map[string]bool{
	"tcp":  true,
	"udp":  true,
	"both": true,
}

// validateService checks that ports, source_ports, and protocol are safe to compile into iptables rules.
// For user-defined services, ICMP and IGMP protocols are blocked.
// For non-ICMP/IGMP protocols, at least one of ports or source_ports is required.
func validateService(ports, sourcePorts, protocol string, isSystem bool) error {
	// ICMP and IGMP are only allowed for system services
	if protocol == "icmp" && !isSystem {
		return fmt.Errorf("ICMP protocol is reserved for system services and cannot be used for user-defined services")
	}
	if protocol == "igmp" && !isSystem {
		return fmt.Errorf("IGMP protocol is reserved for system services and cannot be used for user-defined services")
	}

	// For non-ICMP/IGMP protocols, validate against allowed list
	if protocol != "icmp" && protocol != "igmp" && !validProtocols[protocol] {
		return fmt.Errorf("invalid protocol %q: must be tcp, udp, or both", protocol)
	}

	// ICMP and IGMP don't use ports
	if protocol == "icmp" || protocol == "igmp" {
		return nil
	}

	// For non-ICMP protocols, at least one port type is required
	if ports == "" && sourcePorts == "" {
		return fmt.Errorf("at least one port type (destination ports or source ports) is required for protocol %q", protocol)
	}

	// Validate destination ports format if provided
	if ports != "" && !validPortsRe.MatchString(ports) {
		return fmt.Errorf("invalid destination ports %q: must be digits separated by commas or colons", ports)
	}

	// Validate source ports format if provided
	if sourcePorts != "" && !validPortsRe.MatchString(sourcePorts) {
		return fmt.Errorf("invalid source ports %q: must be digits separated by commas or colons", sourcePorts)
	}

	return nil
}

// --- Services ---

func ListServices(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.QueryContext(r.Context(),
		"SELECT id, name, ports, COALESCE(source_ports, ''), protocol, COALESCE(description, ''), direction_hint, COALESCE(is_system, 0) FROM services")
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query services")
		return
	}
	defer rows.Close()

	type serviceResp struct {
		ID            int    `json:"id"`
		Name          string `json:"name"`
		Ports         string `json:"ports"`
		SourcePorts   string `json:"source_ports"`
		Protocol      string `json:"protocol"`
		Description   string `json:"description"`
		DirectionHint string `json:"direction_hint"`
		IsSystem      bool   `json:"is_system"`
	}

	var servicesData []serviceResp
	for rows.Next() {
		var s serviceResp
		if err := rows.Scan(&s.ID, &s.Name, &s.Ports, &s.SourcePorts, &s.Protocol, &s.Description, &s.DirectionHint, &s.IsSystem); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to scan service")
			return
		}
		servicesData = append(servicesData, s)
	}
	if servicesData == nil {
		servicesData = []serviceResp{}
	}
	common.RespondJSON(w, http.StatusOK, servicesData)
}

func CreateService(w http.ResponseWriter, r *http.Request) {
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

	// User-created services are never system services
	if err := validateService(input.Ports, input.SourcePorts, input.Protocol, false); err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	result, err := db.DB.ExecContext(r.Context(),
		`INSERT INTO services (name, ports, source_ports, protocol, description, direction_hint, is_system)
		VALUES (?, ?, ?, ?, ?, ?, 0)`,
		input.Name, input.Ports, input.SourcePorts, input.Protocol, input.Description, input.DirectionHint)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create service: %v", err))
		return
	}

	id, _ := result.LastInsertId()
	common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func GetService(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid service ID")
		return
	}

	s, err := db.GetService(r.Context(), db.DB.DB, id)
	if err != nil {
		common.RespondError(w, http.StatusNotFound, "service not found")
		return
	}

	common.RespondJSON(w, http.StatusOK, s)
}

func UpdateService(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid service ID")
		return
	}

	// Check if this is a system service
	var isSystem bool
	err = db.DB.QueryRowContext(r.Context(), "SELECT COALESCE(is_system, 0) FROM services WHERE id = ?", id).Scan(&isSystem)
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

	if input.Protocol == "" {
		input.Protocol = "tcp"
	}

	// Pass isSystem flag to validation to allow ICMP for system services
	if err := validateService(input.Ports, input.SourcePorts, input.Protocol, isSystem); err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	_, err = db.DB.ExecContext(r.Context(),
		`UPDATE services SET name = ?, ports = ?, source_ports = ?, protocol = ?, description = ?, direction_hint = ?
		WHERE id = ?`, input.Name, input.Ports, input.SourcePorts, input.Protocol, input.Description, input.DirectionHint, id)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to update service: %v", err))
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func DeleteService(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid service ID")
		return
	}

	// Check if this is a system service
	var isSystem bool
	err = db.DB.QueryRowContext(r.Context(), "SELECT COALESCE(is_system, 0) FROM services WHERE id = ?", id).Scan(&isSystem)
	if err != nil {
		common.RespondError(w, http.StatusNotFound, "service not found")
		return
	}

	if isSystem {
		common.RespondError(w, http.StatusForbidden, "Cannot delete system service")
		return
	}

	_, err = db.DB.ExecContext(r.Context(), "DELETE FROM services WHERE id = ?", id)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete service: %v", err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
