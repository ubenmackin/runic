// Package groups provides group management handlers.
package groups

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"runic/internal/api/common"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
	"runic/internal/models"
	"runic/internal/store"
)

type GroupStore interface {
	ListGroups(ctx context.Context) ([]store.GroupWithCounts, error)
	CreateGroup(ctx context.Context, name, description string) (int64, error)
	GetGroup(ctx context.Context, id int) (models.GroupRow, error)
	GetGroupSQLTx(ctx context.Context, tx *sql.Tx, id int) (models.GroupRow, error)
	UpdateGroup(ctx context.Context, id int, name, description string) error
	UpdateGroupTx(ctx context.Context, tx *sql.Tx, id int, name, description string) error
	GetGroupSystemStatus(ctx context.Context, id int) (bool, error)
	SoftDeleteGroup(ctx context.Context, id int) error
	SoftDeleteGroupTx(ctx context.Context, tx *sql.Tx, id int) error
	ListGroupMembers(ctx context.Context, id int) ([]store.PeerInGroup, error)
	AddGroupMember(ctx context.Context, groupID, peerID int) (int64, error)
	DeleteGroupMember(ctx context.Context, groupID, peerID int) error
	Snapshot(ctx context.Context, action string, groupID int) error
	SnapshotTx(ctx context.Context, tx *sql.Tx, action string, groupID int) error
	CheckDeleteConstraints(ctx context.Context, groupID int) error
	QueueGroupChange(ctx context.Context, changeWorker *common.ChangeWorker, compiler *engine.Compiler, groupID int, changeAction string, summary string)
}

type Handler struct {
	beginner     db.Beginner
	Compiler     *engine.Compiler
	ChangeWorker *common.ChangeWorker
	Store        GroupStore
	PeerStore    *store.PeerStore
}

func NewHandler(beginner db.Beginner, compiler *engine.Compiler, changeWorker *common.ChangeWorker, groupStore GroupStore, peerStore *store.PeerStore) *Handler {
	return &Handler{beginner: beginner, Compiler: compiler, ChangeWorker: changeWorker, Store: groupStore, PeerStore: peerStore}
}

// --- Groups ---

func (h *Handler) ListGroups(w http.ResponseWriter, r *http.Request) {
	groupsData, err := h.Store.ListGroups(r.Context())
	if err != nil {
		log.ErrorContext(r.Context(), "failed to query groups", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to query groups")
		return
	}
	common.RespondJSON(w, http.StatusOK, groupsData)
}

func (h *Handler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		Name        string `json:"name"`
		Description string `json:"description"`
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

	id, err := h.Store.CreateGroup(r.Context(), input.Name, input.Description)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to create group", "error", err)
		common.InternalError(w)
		return
	}

	common.SnapshotOrLog(r.Context(), "group", int(id), "create", func() error {
		return h.Store.Snapshot(r.Context(), "create", int(id))
	})
	common.QueueGroupChangeSummary(r.Context(), h.ChangeWorker, h.Compiler, h.Store, int(id), "create", "created")

	common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (h *Handler) GetGroup(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid group ID")
		return
	}

	g, err := h.Store.GetGroup(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "group not found")
		} else {
			log.ErrorContext(r.Context(), "failed to query group", "error", err)
			common.InternalError(w)
		}
		return
	}

	common.RespondJSON(w, http.StatusOK, g)
}

func (h *Handler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid group ID")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		Name        string `json:"name"`
		Description string `json:"description"`
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

	hasChanges := false
	err = store.RunInTx(r.Context(), h.beginner, func(tx *sql.Tx) error {
		currentGroup, err := h.Store.GetGroupSQLTx(r.Context(), tx, id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return common.NewHTTPError(http.StatusNotFound, "group not found")
			}
			return fmt.Errorf("failed to get group: %w", err)
		}

		nameChanged := input.Name != "" && input.Name != currentGroup.Name
		descChanged := input.Description != currentGroup.Description
		hasChanges = nameChanged || descChanged

		if hasChanges {
			common.SnapshotOrLog(r.Context(), "group", id, "update", func() error {
				return h.Store.SnapshotTx(r.Context(), tx, "update", id)
			})
		}

		if err := h.Store.UpdateGroupTx(r.Context(), tx, id, input.Name, input.Description); err != nil {
			return fmt.Errorf("failed to update group: %w", err)
		}
		return nil
	})

	if err != nil {
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) {
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
		} else {
			log.ErrorContext(r.Context(), "transaction failed", "error", err)
			common.InternalError(w)
		}
		return
	}

	if hasChanges {
		common.QueueGroupChangeSummary(r.Context(), h.ChangeWorker, h.Compiler, h.Store, id, "update", "updated")
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid group ID")
		return
	}

	isSystem, err := h.Store.GetGroupSystemStatus(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "group not found")
		} else {
			log.ErrorContext(r.Context(), "failed to query group system status", "error", err)
			common.InternalError(w)
		}
		return
	}

	if isSystem {
		common.RespondError(w, http.StatusForbidden, "Cannot delete system group")
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

	err = store.RunInTx(r.Context(), h.beginner, func(tx *sql.Tx) error {
		common.SnapshotOrLog(r.Context(), "group", id, "delete", func() error {
			return h.Store.SnapshotTx(r.Context(), tx, "delete", id)
		})
		if err := h.Store.SoftDeleteGroupTx(r.Context(), tx, id); err != nil {
			return fmt.Errorf("soft delete: %w", err)
		}
		return nil
	})
	if err != nil {
		log.ErrorContext(r.Context(), "transaction failed", "error", err)
		common.InternalError(w)
		return
	}

	common.QueueGroupChangeSummary(r.Context(), h.ChangeWorker, h.Compiler, h.Store, id, "delete", "deleted")

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListGroupMembers(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid group ID")
		return
	}

	peers, err := h.Store.ListGroupMembers(r.Context(), id)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to list group members", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to query group members")
		return
	}

	common.RespondJSON(w, http.StatusOK, peers)
}

func (h *Handler) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	groupID, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid group ID")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		PeerID int `json:"peer_id"`
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
	if input.PeerID == 0 {
		common.RespondError(w, http.StatusBadRequest, "peer_id is required")
		return
	}

	common.SnapshotOrLog(r.Context(), "group", groupID, "update", func() error {
		return h.Store.Snapshot(r.Context(), "update", groupID)
	})

	id, err := h.Store.AddGroupMember(r.Context(), groupID, input.PeerID)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to add member", "error", err)
		common.InternalError(w)
		return
	}

	if h.ChangeWorker != nil && h.Compiler != nil {
		hostname, hostnameErr := h.PeerStore.GetPeerHostname(r.Context(), input.PeerID)
		group, groupErr := h.Store.GetGroup(r.Context(), groupID)

		var summary string
		if hostnameErr == nil && groupErr == nil {
			summary = fmt.Sprintf("Peer '%s' added to group '%s'", hostname, group.Name)
		} else {
			summary = "Peer added to group"
		}

		h.ChangeWorker.QueueGroupChange(r.Context(), h.Compiler, groupID, "update", summary)
	}

	common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (h *Handler) DeleteGroupMember(w http.ResponseWriter, r *http.Request) {
	groupID, err := common.ParseIDParam(r, "groupId")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid group ID")
		return
	}

	peerID, err := common.ParseIDParam(r, "peerId")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	common.SnapshotOrLog(r.Context(), "group", groupID, "update", func() error {
		return h.Store.Snapshot(r.Context(), "update", groupID)
	})

	err = h.Store.DeleteGroupMember(r.Context(), groupID, peerID)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to remove peer from group", "error", err)
		common.InternalError(w)
		return
	}

	if h.ChangeWorker != nil && h.Compiler != nil {
		hostname, hostnameErr := h.PeerStore.GetPeerHostname(r.Context(), peerID)
		group, groupErr := h.Store.GetGroup(r.Context(), groupID)

		var summary string
		if hostnameErr == nil && groupErr == nil {
			summary = fmt.Sprintf("Peer '%s' removed from group '%s'", hostname, group.Name)
		} else {
			summary = "Peer removed from group"
		}

		h.ChangeWorker.QueueGroupChange(r.Context(), h.Compiler, groupID, "update", summary)
	}

	w.WriteHeader(http.StatusNoContent)
}

// RegisterReadRoutes registers read-only (GET) routes for the viewer role.
func (h *Handler) RegisterReadRoutes(r *mux.Router) {
	r.HandleFunc("", h.ListGroups).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.GetGroup).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}/members", h.ListGroupMembers).Methods("GET")
}

func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("", h.ListGroups).Methods("GET")
	r.HandleFunc("", h.CreateGroup).Methods("POST")
	r.HandleFunc("/{id:[0-9]+}", h.GetGroup).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.UpdateGroup).Methods("PUT")
	r.HandleFunc("/{id:[0-9]+}", h.DeleteGroup).Methods("DELETE")
	r.HandleFunc("/{id:[0-9]+}/members", h.ListGroupMembers).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}/members", h.AddGroupMember).Methods("POST")
	r.HandleFunc("/{groupId:[0-9]+}/members/{peerId:[0-9]+}", h.DeleteGroupMember).Methods("DELETE")
}
