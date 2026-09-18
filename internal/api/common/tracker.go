// Package common provides shared utilities and constants.
package common

import (
	"context"
	"fmt"
	"time"

	"runic/internal/common/log"
	"runic/internal/engine"
	"runic/internal/models"
)

// SnapshotOrLog calls fn (typically a store.Snapshot call) and logs any error
// before returning it. Callers must fail closed on a non-nil return: for
// pre-mutation snapshots return 500 without mutating, and for snapshots
// inside a transaction return the error to roll back. Proceeding to persist
// or ack 2xx after a snapshot failure would break the snapshot-then-modify
// guarantee and leave no rollback path.
func SnapshotOrLog(ctx context.Context, entityType string, entityID int, action string, fn func() error) error {
	if err := fn(); err != nil {
		log.ErrorContext(ctx, "failed to create snapshot",
			"entity", entityType,
			"id", entityID,
			"action", action,
			"error", err,
		)
		return fmt.Errorf("create %s snapshot %d %s: %w", entityType, entityID, action, err)
	}
	return nil
}

// GroupChangeQueuer is the subset of GroupStore needed to queue a group change.
type GroupChangeQueuer interface {
	GetGroup(ctx context.Context, id int) (models.GroupRow, error)
}

// QueueGroupChangeSummary looks up the group name to build a readable summary
// and queues the change. It returns an error when the worker, compiler,
// store, or id is missing so callers fail the request instead of acking
// success with zero fan-out and losing the DB pending signal. A worker queue
// failure (stopped/full fallback error) is propagated the same way. A nil
// error means the change was queued for background persistence.
func QueueGroupChangeSummary(ctx context.Context, cw *ChangeWorker, compiler *engine.Compiler, store GroupChangeQueuer, id int, action string, verb string) error {
	if cw == nil || compiler == nil || store == nil || id <= 0 {
		log.WarnContext(ctx, "dropping group change summary: missing worker, compiler, store, or invalid id", "group_id", id, "action", action)
		return fmt.Errorf("cannot queue group %d %s: change worker or compiler not available", id, action)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Detach the lookup so a client disconnect cannot degrade the summary
	// to generic after the handler returns.
	lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	group, err := store.GetGroup(lookupCtx, id)
	var summary string
	if err == nil {
		summary = fmt.Sprintf("Group '%s' %s", group.Name, verb)
	} else {
		summary = fmt.Sprintf("Group %s", verb)
	}
	return cw.QueueGroupChange(ctx, compiler, id, action, summary)
}
