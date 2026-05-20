// Package services provides service handlers.
package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"runic/internal/api/common"
	ic "runic/internal/common"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
	"runic/internal/store"
)

type Handler struct {
	beginner     db.Beginner
	Store        *store.ServiceStore
	Compiler     *engine.Compiler
	ChangeWorker *common.ChangeWorker
}

func NewHandler(beginner db.Beginner, serviceStore *store.ServiceStore, compiler *engine.Compiler, changeWorker *common.ChangeWorker) *Handler {
	return &Handler{beginner: beginner, Store: serviceStore, Compiler: compiler, ChangeWorker: changeWorker}
}

// Note: ICMP and IGMP are only allowed for system services, not user-defined services.
var validProtocols = map[string]bool{
	"tcp":  true,
	"udp":  true,
	"both": true,
}

// protocol-only lookup path in GetServiceByPort. This includes system-only
// protocols (icmp, igmp) since the protocol-only path searches system services.
var validLookupProtocols = map[string]bool{
	"tcp":  true,
	"udp":  true,
	"both": true,
	"icmp": true,
	"igmp": true,
}

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

func parseDirectionHint(s string) int {
	switch s {
	case "outbound":
		return 1
	case "both":
		return 2
	default:
		return 0 // inbound
	}
}

// --- Services ---

func (h *Handler) ListServices(w http.ResponseWriter, r *http.Request) {
	servicesData, err := h.Store.ListServices(r.Context())
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query services")
		return
	}

	servicesData = ic.EnsureSlice(servicesData)
	common.RespondJSON(w, http.StatusOK, servicesData)
}

func (h *Handler) CreateService(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		Name          string `json:"name"`
		Ports         string `json:"ports"`
		SourcePorts   string `json:"source_ports"`
		Protocol      string `json:"protocol"`
		Description   string `json:"description"`
		DirectionHint string `json:"direction_hint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

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

	id, err := h.Store.CreateService(r.Context(), input.Name, input.Ports, input.SourcePorts, input.Protocol, input.Description, parseDirectionHint(input.DirectionHint), false)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to create service", "error", err)
		common.InternalError(w)
		return
	}

	common.SnapshotOrLog(r.Context(), "service", int(id), "create", func() error {
		return h.Store.SnapshotService(r.Context(), int(id), "create")
	})
	h.queueServiceChange(r.Context(), int(id), "create", fmt.Sprintf("Service '%s' created", input.Name))

	common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (h *Handler) GetService(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid service ID")
		return
	}

	s, err := h.Store.GetService(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "service not found")
		return
	}
	if err != nil {
		log.ErrorContext(r.Context(), "failed to get service", "error", err)
		common.InternalError(w)
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

	svc, err := h.Store.GetService(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "service not found")
		return
	}
	if err != nil {
		log.ErrorContext(r.Context(), "failed to get service", "error", err)
		common.InternalError(w)
		return
	}

	if svc.IsSystem {
		common.RespondError(w, http.StatusForbidden, "Cannot edit system service")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		Name          string `json:"name"`
		Ports         string `json:"ports"`
		SourcePorts   string `json:"source_ports"`
		Protocol      string `json:"protocol"`
		Description   string `json:"description"`
		DirectionHint string `json:"direction_hint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if input.Name != "" {
		if err := common.ValidateName(input.Name); err != nil {
			common.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if input.Protocol == "" {
		input.Protocol = "tcp"
	}

	if err := validateService(input.Ports, input.SourcePorts, input.Protocol, svc.IsSystem); err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	err = store.RunInTx(r.Context(), h.beginner, func(tx *sql.Tx) error {
		common.SnapshotOrLog(r.Context(), "service", id, "update", func() error {
			return h.Store.SnapshotServiceTx(r.Context(), tx, id, "update")
		})
		if err := h.Store.UpdateServiceTx(r.Context(), tx, id, input.Name, input.Ports, input.SourcePorts, input.Protocol, input.Description, parseDirectionHint(input.DirectionHint)); err != nil {
			return fmt.Errorf("update: %w", err)
		}
		return nil
	})
	if err != nil {
		log.ErrorContext(r.Context(), "transaction failed", "error", err)
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

	svc, err := h.Store.GetService(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "service not found")
		return
	}
	if err != nil {
		log.ErrorContext(r.Context(), "failed to get service", "error", err)
		common.InternalError(w)
		return
	}

	if svc.IsSystem {
		common.RespondError(w, http.StatusForbidden, "Cannot delete system service")
		return
	}

	err = h.Store.CheckDeleteConstraints(r.Context(), id)
	if err != nil {
		constraintErr, ok := err.(*common.DeleteConstraintError)
		if ok {
			common.RespondJSON(w, http.StatusConflict, constraintErr.ToResponse())
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to check constraints")
		return
	}

	common.SnapshotOrLog(r.Context(), "service", id, "delete", func() error {
		return h.Store.SnapshotService(r.Context(), id, "delete")
	})

	if err := h.Store.SoftDeleteService(r.Context(), id); err != nil {
		log.ErrorContext(r.Context(), "failed to delete service", "error", err)
		common.InternalError(w)
		return
	}

	h.queueServiceChange(r.Context(), id, "delete", fmt.Sprintf("Service '%s' deleted", svc.Name))

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) queueServiceChange(ctx context.Context, serviceID int, action, summary string) {
	policyIDs, err := h.Store.FindPoliciesUsingService(ctx, serviceID)
	if err != nil {
		log.ErrorContext(ctx, "failed to find policies for service", "service_id", serviceID, "error", err)
		return
	}

	var allPeers [][]int
	if h.Compiler != nil {
		for _, policyID := range policyIDs {
			affectedPeers, err := h.Compiler.GetAffectedPeersByPolicy(ctx, policyID)
			if err != nil {
				log.ErrorContext(ctx, "Failed to get affected peers for service change", "policy_id", policyID, "error", err)
				continue
			}
			allPeers = append(allPeers, affectedPeers)
		}
	}

	peerIDs := common.MergePeerIDs(allPeers...)
	if len(peerIDs) > 0 {
		h.Store.QueuePeerChange(ctx, h.ChangeWorker, peerIDs, "service", action, serviceID, summary)
	}
}

// RegisterReadRoutes registers read-only (GET) routes for the viewer role.
func (h *Handler) RegisterReadRoutes(r *mux.Router) {
	r.HandleFunc("", h.ListServices).Methods("GET")
	r.HandleFunc("/by-port", h.GetServiceByPort).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.GetService).Methods("GET")
}

func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("", h.ListServices).Methods("GET")
	r.HandleFunc("", h.CreateService).Methods("POST")
	r.HandleFunc("/by-port", h.GetServiceByPort).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.GetService).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.UpdateService).Methods("PUT")
	r.HandleFunc("/{id:[0-9]+}", h.DeleteService).Methods("DELETE")
}

// GetServiceByPort looks up a service by port and optional protocol. When port is "0" or empty and protocol is provided, it performs a protocol-only lookup
// that includes system services (useful for ICMP/IGMP which have no ports).
func (h *Handler) GetServiceByPort(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("port")
	protocol := r.URL.Query().Get("protocol")

	if port == "" || port == "0" {
		if protocol == "" {
			common.RespondError(w, http.StatusBadRequest, "port or protocol parameter required")
			return
		}

		if !validLookupProtocols[protocol] {
			common.RespondError(w, http.StatusBadRequest, "invalid protocol")
			return
		}

		results, err := h.Store.GetServiceByPort(r.Context(), port, protocol)
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to lookup service by protocol")
			return
		}
		if len(results) == 0 {
			common.RespondJSON(w, http.StatusOK, nil)
			return
		}
		common.RespondJSON(w, http.StatusOK, results[0])
		return
	}

	if !engine.ValidPortsRe.MatchString(port) {
		common.RespondError(w, http.StatusBadRequest, "invalid port format")
		return
	}

	results, err := h.Store.GetServiceByPort(r.Context(), port, protocol)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to lookup service by port")
		return
	}
	if len(results) == 0 {
		common.RespondJSON(w, http.StatusOK, nil)
		return
	}
	common.RespondJSON(w, http.StatusOK, results[0])
}
