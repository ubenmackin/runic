// Package common provides shared utilities and constants.
package common

import (
	"context"
	"fmt"

	"runic/internal/common/log"
	"runic/internal/engine"
	"runic/internal/models"
)

// SnapshotOrLog calls fn (typically a store.Snapshot call) and logs any error
// non-fatally. This reduces the 3-line snapshot boilerplate to a single call
// in every create/update/delete handler.
func SnapshotOrLog(ctx context.Context, entityType string, entityID int, action string, fn func() error) {
	if err := fn(); err != nil {
		log.ErrorContext(ctx, "failed to create snapshot",
			"entity", entityType,
			"id", entityID,
			"action", action,
			"error", err,
		)
	}
}

// MergePeerIDs merges multiple slices of peer IDs into a single deduplicated
// slice. This consolidates the map-based dedup logic that appears in both
// policy update handlers and the service queue helper.
func MergePeerIDs(slices ...[]int) []int {
	seen := make(map[int]bool)
	var total int
	for _, s := range slices {
		total += len(s)
	}
	result := make([]int, 0, total)
	for _, s := range slices {
		for _, id := range s {
			if !seen[id] {
				seen[id] = true
				result = append(result, id)
			}
		}
	}
	return result
}

// GroupChangeQueuer is the subset of GroupStore needed to queue a group change.
type GroupChangeQueuer interface {
	GetGroup(ctx context.Context, id int) (models.GroupRow, error)
}

// QueueGroupChangeSummary looks up the group name to build a readable summary
// and queues the change. If the lookup fails a generic summary is used.
// The worker/compiler nil check is done inside so callers don't need to guard.
func QueueGroupChangeSummary(ctx context.Context, cw *ChangeWorker, compiler *engine.Compiler, store GroupChangeQueuer, id int, action string, verb string) {
	if cw == nil || compiler == nil {
		return
	}
	group, err := store.GetGroup(ctx, id)
	var summary string
	if err == nil {
		summary = fmt.Sprintf("Group '%s' %s", group.Name, verb)
	} else {
		summary = fmt.Sprintf("Group %s", action)
	}
	cw.QueueGroupChange(ctx, compiler, id, action, summary)
}
