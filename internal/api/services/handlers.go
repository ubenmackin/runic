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

// validProtocols is the set of allowed protocol values.
var validProtocols = map[string]bool{
	"tcp":  true,
	"udp":  true,
	"icmp": true,
	"both": true,
}

// validateService checks that ports and protocol are safe to compile into iptables rules.
func validateService(ports, protocol string) error {
	if !validProtocols[protocol] {
		return fmt.Errorf("invalid protocol %q: must be tcp, udp, icmp, or both", protocol)
	}
	// ICMP doesn't use ports
	if protocol == "icmp" {
		return nil
	}
	if ports == "" {
		return fmt.Errorf("ports are required for protocol %q", protocol)
	}
	if !validPortsRe.MatchString(ports) {
		return fmt.Errorf("invalid ports %q: must be digits separated by commas or colons", ports)
	}
	return nil
}

// --- Services ---

func ListServices(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.QueryContext(r.Context(),
		"SELECT id, name, ports, protocol, COALESCE(description, ''), direction_hint FROM services")
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query services")
		return
	}
	defer rows.Close()

	type serviceResp struct {
		ID            int    `json:"id"`
		Name          string `json:"name"`
		Ports         string `json:"ports"`
		Protocol      string `json:"protocol"`
		Description   string `json:"description"`
		DirectionHint string `json:"direction_hint"`
	}

	var servicesData []serviceResp
	for rows.Next() {
		var s serviceResp
		if err := rows.Scan(&s.ID, &s.Name, &s.Ports, &s.Protocol, &s.Description, &s.DirectionHint); err != nil {
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

	if err := validateService(input.Ports, input.Protocol); err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	result, err := db.DB.ExecContext(r.Context(),
		`INSERT INTO services (name, ports, protocol, description, direction_hint)
		VALUES (?, ?, ?, ?, ?)`,
		input.Name, input.Ports, input.Protocol, input.Description, input.DirectionHint)
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

	var input struct {
		Name          string `json:"name"`
		Ports         string `json:"ports"`
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
	if err := validateService(input.Ports, input.Protocol); err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	_, err = db.DB.ExecContext(r.Context(),
		`UPDATE services SET name = ?, ports = ?, protocol = ?, description = ?, direction_hint = ?
		WHERE id = ?`,
		input.Name, input.Ports, input.Protocol, input.Description, input.DirectionHint, id)
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

	_, err = db.DB.ExecContext(r.Context(), "DELETE FROM services WHERE id = ?", id)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete service: %v", err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
