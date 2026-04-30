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
	GetGroupTx(ctx context.Context, q db.Querier, id int) (models.GroupRow, error)
	UpdateGroup(ctx context.Context, q db.Querier, id int, name, description string) error
	GetGroupSystemStatus(ctx context.Context, id int) (bool, error)
	SoftDeleteGroup(ctx context.Context, id int) error
	ListGroupMembers(ctx context.Context, id int) ([]store.PeerInGroup, error)
	AddGroupMember(ctx context.Context, groupID, peerID int) (int64, error)
	DeleteGroupMember(ctx context.Context, groupID, peerID int) error
	GetPeerHostname(ctx context.Context, peerID int64) (string, error)
	Snapshot(ctx context.Context, q db.Querier, action string, groupID int) error
}

// Handler provides HTTP handlers for group operations with dependency injection
type Handler struct {
	DB           db.DB
	Compiler     *engine.Compiler
	ChangeWorker *common.ChangeWorker
	Store        GroupStore
}

// NewHandler creates a new groups handler with the given dependencies
func NewHandler(db db.DB, compiler *engine.Compiler, changeWorker *common.ChangeWorker, groupStore GroupStore) *Handler {
	return &Handler{DB: db, Compiler: compiler, ChangeWorker: changeWorker, Store: groupStore}
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
	var input struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
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

	if err := h.Store.Snapshot(r.Context(), h.DB, "create", int(id)); err != nil {
		log.ErrorContext(r.Context(), "failed to create snapshot", "error", err)
	}

	if h.ChangeWorker != nil {
		group, groupErr := h.Store.GetGroup(r.Context(), int(id))

		var summary string
		if groupErr == nil {
			summary = fmt.Sprintf("Group '%s' created", group.Name)
		} else {
			summary = "Group created"
		}

		h.ChangeWorker.QueueGroupChange(r.Context(), h.DB, h.Compiler, int(id), "create", summary)
	}

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

	var input struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
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
	err = store.RunInTx(r.Context(), h.DB, func(tx *sql.Tx) error {
		currentGroup, err := h.Store.GetGroupTx(r.Context(), tx, id)
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
			if err := h.Store.Snapshot(r.Context(), tx, "update", id); err != nil {
				log.ErrorContext(r.Context(), "failed to create snapshot", "error", err)
			}
		}

		if err := h.Store.UpdateGroup(r.Context(), tx, id, input.Name, input.Description); err != nil {
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

	if h.ChangeWorker != nil && hasChanges {
		group, groupErr := h.Store.GetGroup(r.Context(), id)
		var summary string
		if groupErr == nil {
			summary = fmt.Sprintf("Group '%s' updated", group.Name)
		} else {
			summary = "Group updated"
		}
		h.ChangeWorker.QueueGroupChange(r.Context(), h.DB, h.Compiler, id, "update", summary)
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

	err = common.CheckGroupDeleteConstraints(r.Context(), h.DB, id)
	if err != nil {
		var constraintErr *common.DeleteConstraintError
		if errors.As(err, &constraintErr) {
			common.RespondJSON(w, http.StatusConflict, constraintErr.ToResponse())
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to check constraints")
		return
	}

	if err := h.Store.Snapshot(r.Context(), h.DB, "delete", id); err != nil {
		log.ErrorContext(r.Context(), "failed to create snapshot", "error", err)
	}

	err = h.Store.SoftDeleteGroup(r.Context(), id)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to soft delete group", "error", err)
		common.InternalError(w)
		return
	}

	if h.ChangeWorker != nil {
		h.ChangeWorker.QueueGroupChange(r.Context(), h.DB, h.Compiler, id, "delete", "Group deleted")
	}

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

	var input struct {
		PeerID int `json:"peer_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if input.PeerID == 0 {
		common.RespondError(w, http.StatusBadRequest, "peer_id is required")
		return
	}

	if err := h.Store.Snapshot(r.Context(), h.DB, "update", groupID); err != nil {
		log.ErrorContext(r.Context(), "failed to create snapshot", "error", err)
	}

	id, err := h.Store.AddGroupMember(r.Context(), groupID, input.PeerID)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to add member", "error", err)
		common.InternalError(w)
		return
	}

	if h.ChangeWorker != nil {
		hostname, hostnameErr := h.Store.GetPeerHostname(r.Context(), int64(input.PeerID))
		group, groupErr := h.Store.GetGroup(r.Context(), groupID)

		var summary string
		if hostnameErr == nil && groupErr == nil {
			summary = fmt.Sprintf("Peer '%s' added to group '%s'", hostname, group.Name)
		} else {
			summary = "Peer added to group"
		}

		h.ChangeWorker.QueueGroupChange(r.Context(), h.DB, h.Compiler, groupID, "update", summary)
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

	if err := h.Store.Snapshot(r.Context(), h.DB, "update", groupID); err != nil {
		log.ErrorContext(r.Context(), "failed to create snapshot", "error", err)
	}

	err = h.Store.DeleteGroupMember(r.Context(), groupID, peerID)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to remove peer from group", "error", err)
		common.InternalError(w)
		return
	}

	if h.ChangeWorker != nil {
		hostname, hostnameErr := h.Store.GetPeerHostname(r.Context(), int64(peerID))
		group, groupErr := h.Store.GetGroup(r.Context(), groupID)

		var summary string
		if hostnameErr == nil && groupErr == nil {
			summary = fmt.Sprintf("Peer '%s' removed from group '%s'", hostname, group.Name)
		} else {
			summary = "Peer removed from group"
		}

		h.ChangeWorker.QueueGroupChange(r.Context(), h.DB, h.Compiler, groupID, "update", summary)
	}

	w.WriteHeader(http.StatusNoContent)
}

// RegisterRoutes adds group routes to the given router.
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
