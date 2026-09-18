// Package groups provides group management handlers.
package groups

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/mattn/go-sqlite3"

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
	UpdateGroup(ctx context.Context, id int, name, description string) error
	UpdateGroupTx(ctx context.Context, tx *sql.Tx, id int, name, description string) error
	GetGroupSystemStatus(ctx context.Context, id int) (bool, error)
	SoftDeleteGroup(ctx context.Context, id int) error
	SoftDeleteGroupTx(ctx context.Context, tx *sql.Tx, id int) error
	ListGroupMembers(ctx context.Context, id int) ([]store.PeerInGroup, error)
	AddGroupMember(ctx context.Context, groupID, peerID int) (int64, error)
	AddGroupMemberTx(ctx context.Context, tx *sql.Tx, groupID, peerID int) (int64, error)
	DeleteGroupMember(ctx context.Context, groupID, peerID int) (bool, error)
	DeleteGroupMemberTx(ctx context.Context, tx *sql.Tx, groupID, peerID int) (bool, error)
	Snapshot(ctx context.Context, action string, groupID int) error
	SnapshotTx(ctx context.Context, tx *sql.Tx, action string, groupID int) error
	CheckDeleteConstraints(ctx context.Context, groupID int) error
	CheckDeleteConstraintsTx(ctx context.Context, q db.Querier, groupID int) error
	QueueGroupChange(ctx context.Context, changeWorker *common.ChangeWorker, compiler *engine.Compiler, groupID int, changeAction string, summary string) error
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

	// Fail closed on snapshot failure: without a snapshot there is no
	// rollback path, so do not ack success with a lost snapshot.
	if err := common.SnapshotOrLog(r.Context(), "group", int(id), "create", func() error {
		return h.Store.Snapshot(r.Context(), "create", int(id))
	}); err != nil {
		log.ErrorContext(r.Context(), "failed to create snapshot for group", "group_id", id, "error", err)
		common.RespondError(w, http.StatusInternalServerError, "group created but snapshot incomplete; manual recompile required")
		return
	}
	// Fail closed when the change worker or compiler is unavailable:
	// acking 201 with zero fan-out would lose the DB pending signal.
	if err := common.QueueGroupChangeSummary(r.Context(), h.ChangeWorker, h.Compiler, h.Store, int(id), "create", "created"); err != nil {
		log.ErrorContext(r.Context(), "failed to queue group change", "group_id", id, "error", err)
		common.RespondError(w, http.StatusInternalServerError, "group created but pending signal incomplete; manual recompile required")
		return
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

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
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

	if input.Name != nil && *input.Name != "" {
		if err := common.ValidateName(*input.Name); err != nil {
			common.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	hasChanges := false
	err = db.RunInTx(r.Context(), h.beginner, func(ctx context.Context, tx *sql.Tx) error {
		currentGroup, err := h.Store.GetGroupTx(ctx, tx, id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return common.NewHTTPError(http.StatusNotFound, "group not found")
			}
			return fmt.Errorf("failed to get group: %w", err)
		}

		// Presence-tracked change detection: an omitted field (nil) means
		// "preserve current" and must not count as a change, snapshot, or
		// fan-out. Only an explicitly provided value differing from current
		// marks the row dirty. An explicit empty name ("") still preserves
		// via COALESCE(NULLIF(...)) in UpdateGroupTx.
		nameChanged := input.Name != nil && *input.Name != "" && *input.Name != currentGroup.Name
		descChanged := input.Description != nil && *input.Description != currentGroup.Description
		hasChanges = nameChanged || descChanged

		if !hasChanges {
			return nil
		}

		// Fail closed on snapshot failure: return the error so the
		// transaction rolls back instead of persisting without a rollback
		// path.
		if err := common.SnapshotOrLog(ctx, "group", id, "update", func() error {
			return h.Store.SnapshotTx(ctx, tx, "update", id)
		}); err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}

		effectiveName := ""
		if input.Name != nil {
			effectiveName = *input.Name
		}
		effectiveDesc := currentGroup.Description
		if input.Description != nil {
			effectiveDesc = *input.Description
		}
		if err := h.Store.UpdateGroupTx(ctx, tx, id, effectiveName, effectiveDesc); err != nil {
			// A concurrent delete between the GetGroupTx above and the
			// update surfaces as ErrGroupNotFound (UPDATE WHERE
			// is_pending_delete=0 hits 0 rows); map to 404 like the
			// policy update path instead of 500.
			if errors.Is(err, store.ErrGroupNotFound) {
				return common.NewHTTPError(http.StatusNotFound, "group not found")
			}
			return fmt.Errorf("failed to update group: %w", err)
		}
		return nil
	})

	if err != nil {
		var httpErr *common.HTTPError
		switch {
		case errors.As(err, &httpErr):
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
		case errors.Is(err, store.ErrGroupNotFound) || errors.Is(err, sql.ErrNoRows):
			// Snapshot-missing is normalized to ErrGroupNotFound in the
			// store; map a TOCTOU delete to 404 instead of 500.
			common.RespondError(w, http.StatusNotFound, "group not found")
		default:
			log.ErrorContext(r.Context(), "transaction failed", "error", err)
			common.InternalError(w)
		}
		return
	}

	if hasChanges {
		// Fail closed when the change worker or compiler is unavailable:
		// acking 200 with zero fan-out would lose the DB pending signal.
		if err := common.QueueGroupChangeSummary(r.Context(), h.ChangeWorker, h.Compiler, h.Store, id, "update", "updated"); err != nil {
			log.ErrorContext(r.Context(), "failed to queue group change", "group_id", id, "error", err)
			common.RespondError(w, http.StatusInternalServerError, "group updated but pending signal incomplete; manual recompile required")
			return
		}
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

	err = db.RunInTx(r.Context(), h.beginner, func(ctx context.Context, tx *sql.Tx) error {
		if err := common.SnapshotOrLog(ctx, "group", id, "delete", func() error {
			return h.Store.SnapshotTx(ctx, tx, "delete", id)
		}); err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
		// Re-check constraints inside the Tx: the pre-check above is a
		// fast 409, but a policy created between that check and the commit
		// must still block the delete instead of leaving a constrained
		// group soft-deleted (TOCTOU).
		if err := h.Store.CheckDeleteConstraintsTx(ctx, tx, id); err != nil {
			return err
		}
		if err := h.Store.SoftDeleteGroupTx(ctx, tx, id); err != nil {
			if errors.Is(err, store.ErrGroupNotFound) {
				return common.NewHTTPError(http.StatusNotFound, "group not found")
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
		// A concurrent delete between the pre-check and the Tx surfaces
		// as ErrGroupNotFound (soft delete) or as a snapshot miss
		// normalized to ErrGroupNotFound; both map to 404 like the
		// policy delete path instead of 500.
		if errors.Is(err, store.ErrGroupNotFound) || errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "group not found")
			return
		}
		log.ErrorContext(r.Context(), "transaction failed", "error", err)
		common.InternalError(w)
		return
	}

	// Fail closed when the change worker or compiler is unavailable:
	// acking 204 with zero fan-out would lose the DB pending signal.
	if err := common.QueueGroupChangeSummary(r.Context(), h.ChangeWorker, h.Compiler, h.Store, id, "delete", "deleted"); err != nil {
		log.ErrorContext(r.Context(), "failed to queue group change", "group_id", id, "error", err)
		common.RespondError(w, http.StatusInternalServerError, "group deleted but pending signal incomplete; manual recompile required")
		return
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

// isGroupMemberForeignKeyError reports whether err is a SQLite foreign key
// failure from the group_members INSERT (a concurrent peer or group delete
// between the pre-checks and the insert). It follows the sqlite3
// ExtendedCode pattern in internal/api/auth/handlers.go, with a message
// fallback so wrapped driver errors still match.
func isGroupMemberForeignKeyError(err error) bool {
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintForeignKey {
		return true
	}
	return strings.Contains(err.Error(), "FOREIGN KEY constraint failed")
}

func (h *Handler) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	// Validate request IDs first so malformed IDs map to 400 even when
	// dependencies are unavailable (which maps to 500 below).
	groupID, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid group ID")
		return
	}

	// Fail closed upfront before any store dereference: a nil dependency
	// must 500 instead of panicking on use or acking success with a lost
	// pending signal.
	if h.Store == nil || h.PeerStore == nil || h.ChangeWorker == nil || h.Compiler == nil || h.beginner == nil {
		log.ErrorContext(r.Context(), "change worker, compiler, or store not available; failing group member add to preserve pending signal")
		common.RespondError(w, http.StatusInternalServerError, "peer added but pending signal incomplete; manual recompile required")
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

	// Pre-validate group and peer so non-existent IDs map to 404 instead
	// of surfacing as a 500 FK failure from the INSERT below.
	if _, err := h.Store.GetGroup(r.Context(), groupID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "group not found")
		} else {
			log.ErrorContext(r.Context(), "failed to query group", "error", err)
			common.InternalError(w)
		}
		return
	}
	if _, err := h.PeerStore.GetPeerHostname(r.Context(), input.PeerID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "peer not found")
		} else {
			log.ErrorContext(r.Context(), "failed to query peer", "error", err)
			common.InternalError(w)
		}
		return
	}

	// Pre-check for duplicate membership so a re-add maps to 409 instead
	// of 201. The store also guards via RowsAffected==0 for races, but
	// checking here avoids an orphan pre-snapshot and does not rely on
	// LastInsertId, which is unreliable for ignored rows.
	members, err := h.Store.ListGroupMembers(r.Context(), groupID)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to list group members", "error", err)
		common.InternalError(w)
		return
	}
	for _, m := range members {
		if m.ID == input.PeerID {
			common.RespondError(w, http.StatusConflict, "peer already in group")
			return
		}
	}
	// Snapshot pre-mutation so rollback restores pre-add members.
	// change_snapshots is UNIQUE(entity_type, entity_id) INSERT OR IGNORE,
	// so the first snapshot wins; snapshotting post-add would store
	// post-add members and make rollback a no-op.
	// Fail closed on snapshot failure: without a snapshot there is no
	// rollback path, so do not persist the membership. The snapshot and
	// the insert commit atomically in one Tx so a failed insert cannot
	// leave an orphan snapshot.
	var id int64
	err = db.RunInTx(r.Context(), h.beginner, func(ctx context.Context, tx *sql.Tx) error {
		if err := common.SnapshotOrLog(ctx, "group", groupID, "update", func() error {
			return h.Store.SnapshotTx(ctx, tx, "update", groupID)
		}); err != nil {
			// The membership has not been persisted yet, so report
			// that the member was not added (not "peer added").
			if errors.Is(err, store.ErrGroupNotFound) || errors.Is(err, sql.ErrNoRows) {
				return common.NewHTTPError(http.StatusNotFound, "group not found")
			}
			return common.NewHTTPError(http.StatusInternalServerError, "failed to create snapshot; member not added", err)
		}
		memberID, err := h.Store.AddGroupMemberTx(ctx, tx, groupID, input.PeerID)
		if err != nil {
			// A concurrent peer delete between the GetPeerHostname
			// pre-check above and the INSERT surfaces as an FK failure
			// (or sql.ErrNoRows); map to 404 like the pre-check instead
			// of 500.
			if errors.Is(err, sql.ErrNoRows) || isGroupMemberForeignKeyError(err) {
				return common.NewHTTPError(http.StatusNotFound, "peer not found")
			}
			return fmt.Errorf("add member: %w", err)
		}
		// INSERT OR IGNORE skips duplicates without error; the store maps
		// RowsAffected==0 to id==0 (LastInsertId is unreliable for ignored
		// rows and may return a prior id). Never ack 201 with {"id":0}:
		// the membership already exists, so report a conflict instead of a
		// phantom create. This also covers a race where a concurrent add
		// wins between the pre-check above and the INSERT.
		if memberID == 0 {
			return common.NewHTTPError(http.StatusConflict, "peer already in group")
		}
		id = memberID
		return nil
	})
	if err != nil {
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) {
			if httpErr.StatusCode == http.StatusInternalServerError {
				log.ErrorContext(r.Context(), "failed to create snapshot for group member add", "group_id", groupID, "error", httpErr.Err)
			}
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
			return
		}
		log.ErrorContext(r.Context(), "failed to add member", "error", err)
		common.InternalError(w)
		return
	}

	// Detach summary lookups from the request context (mirroring
	// QueueGroupChangeSummary) so a client disconnect cannot degrade the
	// summary to generic after the handler returns. Each lookup gets its
	// own timeout budget so the first cannot starve the second.
	hostnameCtx, hostnameCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	hostname, hostnameErr := h.PeerStore.GetPeerHostname(hostnameCtx, input.PeerID)
	hostnameCancel()
	groupCtx, groupCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	group, groupErr := h.Store.GetGroup(groupCtx, groupID)
	groupCancel()

	var summary string
	if hostnameErr == nil && groupErr == nil {
		summary = fmt.Sprintf("Peer '%s' added to group '%s'", hostname, group.Name)
	} else {
		summary = "Peer added to group"
	}

	// Fail closed on synchronous queue failures (stopped/full fallback
	// errors): acking 201 after the fallback dropped the change would lose
	// the DB pending signal.
	if err := h.ChangeWorker.QueueGroupChange(r.Context(), h.Compiler, groupID, "update", summary); err != nil {
		log.ErrorContext(r.Context(), "failed to queue group change", "group_id", groupID, "error", err)
		common.RespondError(w, http.StatusInternalServerError, "peer added but pending signal incomplete; manual recompile required")
		return
	}

	common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (h *Handler) DeleteGroupMember(w http.ResponseWriter, r *http.Request) {
	// Validate request IDs first so malformed IDs map to 400 even when
	// dependencies are unavailable (which maps to 500 below).
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

	// Fail closed upfront before any store dereference: a nil dependency
	// must 500 instead of panicking on use or acking success with a lost
	// pending signal.
	if h.Store == nil || h.PeerStore == nil || h.ChangeWorker == nil || h.Compiler == nil || h.beginner == nil {
		log.ErrorContext(r.Context(), "change worker, compiler, or store not available; failing group member delete to preserve pending signal")
		common.RespondError(w, http.StatusInternalServerError, "peer removed but pending signal incomplete; manual recompile required")
		return
	}

	// Pre-validate group existence so a DELETE on a missing group maps to
	// 404 instead of an idempotent 204: ListGroupMembers on a missing group
	// returns empty/nil, which would otherwise short-circuit as a no-op.
	if _, err := h.Store.GetGroup(r.Context(), groupID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "group not found")
		} else {
			log.ErrorContext(r.Context(), "failed to query group", "error", err)
			common.InternalError(w)
		}
		return
	}

	// No-op short-circuit: a DELETE for a non-member must stay idempotent
	// 204 without creating a snapshot row or pending rows when there is no
	// diff. Pre-check membership before snapshotting so the snapshot (which
	// captures pre-delete members for rollback) and the fan-out are skipped
	// for no-ops.
	members, err := h.Store.ListGroupMembers(r.Context(), groupID)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to list group members", "error", err)
		common.InternalError(w)
		return
	}
	isMember := false
	for _, m := range members {
		if m.ID == peerID {
			isMember = true
			break
		}
	}
	if !isMember {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Snapshot pre-mutation so rollback restores the pre-delete members.
	// change_snapshots is UNIQUE(entity_type, entity_id) INSERT OR IGNORE,
	// so the first snapshot wins; snapshotting post-delete would store
	// post-delete members and rollback would not restore the removed
	// member. Fail closed on snapshot failure: do not mutate without a
	// rollback path. The snapshot and the delete commit atomically in one
	// Tx so a failed delete cannot leave an orphan snapshot.
	var deleted bool
	err = db.RunInTx(r.Context(), h.beginner, func(ctx context.Context, tx *sql.Tx) error {
		if err := common.SnapshotOrLog(ctx, "group", groupID, "update", func() error {
			return h.Store.SnapshotTx(ctx, tx, "update", groupID)
		}); err != nil {
			// The membership has not been removed yet, so report
			// that the member was not removed (not "peer removed").
			if errors.Is(err, store.ErrGroupNotFound) || errors.Is(err, sql.ErrNoRows) {
				return common.NewHTTPError(http.StatusNotFound, "group not found")
			}
			return common.NewHTTPError(http.StatusInternalServerError, "failed to create snapshot; member not removed", err)
		}
		wasDeleted, err := h.Store.DeleteGroupMemberTx(ctx, tx, groupID, peerID)
		if err != nil {
			return fmt.Errorf("delete member: %w", err)
		}
		deleted = wasDeleted
		return nil
	})
	if err != nil {
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) {
			if httpErr.StatusCode == http.StatusInternalServerError {
				log.ErrorContext(r.Context(), "failed to create snapshot for group member delete", "group_id", groupID, "error", httpErr.Err)
			}
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
			return
		}
		log.ErrorContext(r.Context(), "failed to remove peer from group", "error", err)
		common.InternalError(w)
		return
	}
	// A concurrent delete may have won between the pre-check above and the
	// DELETE: RowsAffected==0 means no diff, so skip fan-out and keep the
	// idempotent 204 (the pre-snapshot orphan is harmless, first wins).
	if !deleted {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Detach summary lookups from the request context (mirroring
	// QueueGroupChangeSummary) so a client disconnect cannot degrade the
	// summary to generic after the handler returns. Each lookup gets its
	// own timeout budget so the first cannot starve the second.
	hostnameCtx, hostnameCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	hostname, hostnameErr := h.PeerStore.GetPeerHostname(hostnameCtx, peerID)
	hostnameCancel()
	groupCtx, groupCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	group, groupErr := h.Store.GetGroup(groupCtx, groupID)
	groupCancel()

	var summary string
	if hostnameErr == nil && groupErr == nil {
		summary = fmt.Sprintf("Peer '%s' removed from group '%s'", hostname, group.Name)
	} else {
		summary = "Peer removed from group"
	}

	// Fail closed on synchronous queue failures (stopped/full fallback
	// errors): acking 204 after the fallback dropped the change would lose
	// the DB pending signal.
	queueErr := h.ChangeWorker.QueueGroupChange(r.Context(), h.Compiler, groupID, "update", summary)
	// Conservative superset: the removed peer is no longer a member, so the
	// post-mutation group fan-out above cannot resolve it via
	// GetAffectedPeersByPolicy, yet its bundle still embeds the group.
	// Queue an explicit peer change so its pending signal is not lost with
	// no pending_changes row and a 204 ack. Skip only when the peer is
	// definitively gone (sql.ErrNoRows: no bundle to mark stale, preserves
	// idempotent 204 for non-existent peers); on any other lookup outcome
	// queue conservatively so a transient lookup failure cannot under-mark.
	var peerErr error
	if !errors.Is(hostnameErr, sql.ErrNoRows) {
		peerErr = h.ChangeWorker.QueuePeerChange(r.Context(), []int{peerID}, "group", "update", groupID, summary)
	}
	if joined := errors.Join(queueErr, peerErr); joined != nil {
		log.ErrorContext(r.Context(), "failed to queue group change", "group_id", groupID, "error", joined)
		common.RespondError(w, http.StatusInternalServerError, "peer removed but pending signal incomplete; manual recompile required")
		return
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
