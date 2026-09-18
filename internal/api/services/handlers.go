// Package services provides service handlers.
package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

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

	// Fail closed on snapshot failure: without a snapshot there is no
	// rollback path, so do not ack success with a lost snapshot.
	if err := common.SnapshotOrLog(r.Context(), "service", int(id), "create", func() error {
		return h.Store.SnapshotService(r.Context(), int(id), "create")
	}); err != nil {
		log.ErrorContext(r.Context(), "failed to create snapshot for service", "service_id", id, "error", err)
		common.RespondError(w, http.StatusInternalServerError, "service created but snapshot incomplete; manual recompile required")
		return
	}
	// Fail-closed pending fan-out contract (unified across groups, services,
	// and policies; see docs/api/openapi.yaml): the service row above is
	// already persisted, but a fan-out failure must fail the request with 500
	// so clients uniformly detect the lost pending signal instead of
	// receiving 2xx with zero pending_changes rows. For POST, list services
	// before retrying to avoid creating a duplicate.
	if err := h.queueServiceChange(r.Context(), int(id), "create", fmt.Sprintf("Service '%s' created", input.Name)); err != nil {
		log.ErrorContext(r.Context(), "failed to queue service change", "service_id", id, "error", err)
		common.RespondError(w, http.StatusInternalServerError, "service created but pending signal incomplete; manual recompile required")
		return
	}

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

func (h *Handler) persistServiceUpdateTx(ctx context.Context, id int, input *struct {
	Name          string
	Ports         string
	SourcePorts   string
	Protocol      string
	Description   string
	DirectionHint string
}) error {
	// Snapshot inside the transaction (groups pattern): the snapshot and the
	// update commit atomically, so a failed update cannot leave an orphan
	// snapshot that blocks the true first-change snapshot (INSERT OR IGNORE
	// first-wins). A snapshot failure rolls back the whole tx (fail closed).
	return db.RunInTx(ctx, h.beginner, func(ctx context.Context, tx *sql.Tx) error {
		if err := h.Store.SnapshotServiceTx(ctx, tx, id, "update"); err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
		if err := h.Store.UpdateServiceTx(ctx, tx, id, input.Name, input.Ports, input.SourcePorts, input.Protocol, input.Description, parseDirectionHint(input.DirectionHint)); err != nil {
			return fmt.Errorf("update: %w", err)
		}
		return nil
	})
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

	if input.Name == "" {
		common.RespondError(w, http.StatusBadRequest, "name is required")
		return
	} else if err := common.ValidateName(input.Name); err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if input.Protocol == "" {
		input.Protocol = "tcp"
	}

	// svc.IsSystem is always false here: system services were rejected with
	// 403 above, so pass false explicitly instead of threading the dead
	// parameter.
	if err := validateService(input.Ports, input.SourcePorts, input.Protocol, false); err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	txInput := &struct {
		Name          string
		Ports         string
		SourcePorts   string
		Protocol      string
		Description   string
		DirectionHint string
	}{
		Name:          input.Name,
		Ports:         input.Ports,
		SourcePorts:   input.SourcePorts,
		Protocol:      input.Protocol,
		Description:   input.Description,
		DirectionHint: input.DirectionHint,
	}
	if err := h.persistServiceUpdateTx(r.Context(), id, txInput); err != nil {
		// Snapshot-missing is normalized to ErrServiceNotFound in the
		// store, but also accept sql.ErrNoRows defensively so a TOCTOU
		// delete between GetService and the Tx snapshot maps to 404.
		if errors.Is(err, store.ErrServiceNotFound) || errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "service not found")
			return
		}
		log.ErrorContext(r.Context(), "transaction failed", "error", err)
		common.InternalError(w)
		return
	}

	// Fail-closed pending fan-out contract (unified across groups, services,
	// and policies; see docs/api/openapi.yaml): the mutation above already
	// succeeded, but a fan-out failure must fail the request with 500 so
	// clients uniformly detect the lost pending signal.
	if err := h.queueServiceChange(r.Context(), id, "update", fmt.Sprintf("Service '%s' updated", input.Name)); err != nil {
		log.ErrorContext(r.Context(), "failed to queue service change", "service_id", id, "error", err)
		common.RespondError(w, http.StatusInternalServerError, "service updated but pending signal incomplete; manual recompile required")
		return
	}

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
		var constraintErr *common.DeleteConstraintError
		if errors.As(err, &constraintErr) {
			common.RespondJSON(w, http.StatusConflict, constraintErr.ToResponse())
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to check constraints")
		return
	}

	// Snapshot inside the transaction (groups/policy pattern): the snapshot
	// and the delete commit atomically, so a failed delete cannot leave an
	// orphan snapshot that blocks the true first-change snapshot (INSERT OR
	// IGNORE first-wins). A snapshot failure rolls back the whole tx (fail
	// closed). Constraints are re-checked inside the Tx: the pre-check
	// above is a fast 409, but a policy created between that check and the
	// commit must still block the delete instead of leaving a constrained
	// service soft-deleted (TOCTOU).
	err = db.RunInTx(r.Context(), h.beginner, func(ctx context.Context, tx *sql.Tx) error {
		if err := common.SnapshotOrLog(ctx, "service", id, "delete", func() error {
			return h.Store.SnapshotServiceTx(ctx, tx, id, "delete")
		}); err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
		if err := h.Store.CheckDeleteConstraintsTx(ctx, tx, id); err != nil {
			return err
		}
		if err := h.Store.SoftDeleteServiceTx(ctx, tx, id); err != nil {
			if errors.Is(err, store.ErrServiceNotFound) {
				return common.NewHTTPError(http.StatusNotFound, "service not found")
			}
			return fmt.Errorf("soft delete: %w", err)
		}
		return nil
	})
	if err != nil {
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) {
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
			return
		}
		var constraintErr *common.DeleteConstraintError
		if errors.As(err, &constraintErr) {
			common.RespondJSON(w, http.StatusConflict, constraintErr.ToResponse())
			return
		}
		// A concurrent delete between the pre-check GetService and the Tx
		// surfaces as ErrServiceNotFound (soft delete) or as a snapshot
		// miss normalized to ErrServiceNotFound; both map to 404 like the
		// policy delete path instead of 500.
		if errors.Is(err, store.ErrServiceNotFound) || errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "service not found")
			return
		}
		log.ErrorContext(r.Context(), "transaction failed", "error", err)
		common.InternalError(w)
		return
	}

	// Fail-closed pending fan-out contract (unified across groups, services,
	// and policies; see docs/api/openapi.yaml): the mutation above already
	// succeeded, but a fan-out failure must fail the request with 500 so
	// clients uniformly detect the lost pending signal. Success stays 204 No
	// Content, so a fan-out failure never diverges as 200-with-body on the
	// same operation.
	if err := h.queueServiceChange(r.Context(), id, "delete", fmt.Sprintf("Service '%s' deleted", svc.Name)); err != nil {
		log.ErrorContext(r.Context(), "failed to queue service change", "service_id", id, "error", err)
		common.RespondError(w, http.StatusInternalServerError, "service deleted but pending signal incomplete; manual recompile required")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) queueServiceChange(ctx context.Context, serviceID int, action, summary string) error {
	// Detach from the request context so a client disconnect cannot
	// cancel the resolution and lose pending rows. Any resolution failure
	// is returned so callers fail the request instead of acking success
	// with zero fan-out. Each stage gets its own timeout budget so the
	// policy lookup cannot starve the peer resolution budget.
	// Service fan-out uses the single shared helper
	// (db.FindPolicyIDsByService via Store.FindPoliciesUsingService, also
	// used by the importer) so the service_id predicate cannot diverge.
	if ctx == nil {
		ctx = context.Background()
	}
	findCtx, findCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	policyIDs, err := h.Store.FindPoliciesUsingService(findCtx, serviceID)
	findCancel()
	if err != nil {
		return fmt.Errorf("find policies for service %d: %w", serviceID, err)
	}

	var allPeers [][]int
	var resolveErr error
	// Fail closed when policies exist but the compiler is unavailable:
	// skipping resolution would ack success with zero fan-out and lose the
	// DB pending signal.
	if len(policyIDs) > 0 && h.Compiler == nil {
		return fmt.Errorf("compiler not available for service %d with %d policies", serviceID, len(policyIDs))
	}
	if h.Compiler != nil && len(policyIDs) > 0 {
		compilerCtx, compilerCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		affectedByPolicy, err := h.Compiler.GetAffectedPeersByPolicies(compilerCtx, policyIDs)
		compilerCancel()
		// Merge partial results even on error so one bad policy does not
		// drop the peers of the good policies.
		for _, policyID := range policyIDs {
			allPeers = append(allPeers, affectedByPolicy[policyID])
		}
		resolveErr = err
	}

	peerIDs := ic.MergePeerIDs(allPeers...)
	if len(peerIDs) > 0 {
		// Synchronous queue failures (stopped/full fallback errors) are
		// propagated so callers fail the request instead of acking success
		// with a lost signal.
		if err := h.Store.QueuePeerChange(ctx, h.ChangeWorker, peerIDs, "service", action, serviceID, summary); err != nil {
			return fmt.Errorf("queue peer change for service %d: %w", serviceID, err)
		}
	}
	if resolveErr != nil {
		// Partial signal already queued above; still report the failure so
		// the caller fails the request instead of acking full success.
		log.ErrorContext(ctx, "partial failure resolving affected peers for service", "service_id", serviceID, "error", resolveErr)
		return fmt.Errorf("get affected peers for service %d: %w", serviceID, resolveErr)
	}
	return nil
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
