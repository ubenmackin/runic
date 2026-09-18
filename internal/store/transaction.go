// Package store provides data access layer for groups, policies, and transactions.
package store

import (
	"context"
	"database/sql"
	"fmt"

	"runic/internal/change"
	ic "runic/internal/common"
	"runic/internal/common/log"
	"runic/internal/db"
)

// execUpdate executes an UPDATE statement and returns notFoundErr if no rows were affected.
// The querier can be a *sql.Tx (for transactional use) or a db.DB (for direct use).
func execUpdate(ctx context.Context, q db.Querier, query string, notFoundErr error, args ...any) error {
	result, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("exec update: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return notFoundErr
	}
	return nil
}

// softDelete marks an entity as pending-delete in the specified table.
// Returns notFoundErr if the entity does not exist or is already soft-deleted.
// Returns an error if the table is not in the db allowedTables safelist.
func softDelete(ctx context.Context, q db.Querier, table string, id int, notFoundErr error) error {
	if !db.IsAllowedTable(table) {
		return fmt.Errorf("softDelete: table %q not in safelist", table)
	}
	query := fmt.Sprintf("UPDATE %s SET is_pending_delete = 1 WHERE id = ? AND is_pending_delete = 0", table)
	return execUpdate(ctx, q, query, notFoundErr, id)
}

// getNameByID returns the name column value for a given table and ID.
// whereSuffix is appended to the WHERE clause (e.g. " AND is_pending_delete = 0").
// errLabel is used in the error message (e.g. "group" → "get group name by id").
func getNameByID(ctx context.Context, q db.Querier, table string, id int, whereSuffix, errLabel string) (string, error) {
	if !db.IsAllowedTable(table) {
		return "", fmt.Errorf("getNameByID: table %q not in safelist", table)
	}
	var name string
	err := q.QueryRowContext(ctx, "SELECT name FROM "+table+" WHERE id = ?"+whereSuffix, id).Scan(&name)
	if err != nil {
		return "", fmt.Errorf("get %s name by id: %w", errLabel, err)
	}
	return name, nil
}

// queryRows executes a query, iterates rows with a scan function, checks rows.Err(),
// and returns an EnsureSlice'd result. This eliminates the repetitive query→defer→loop→rows.Err()
// boilerplate pattern.
//
// Row-scan contract (unified with engine queryPeerIDs/findPoliciesByGroup):
// fail-fast. A single corrupt row aborts the whole read with an error instead
// of being skipped, so one bad row can never silently drop constraint or
// fan-out data and lose the DB pending signal.
func queryRows[T any](ctx context.Context, q db.Querier, query string, args []any, errLabel string, scanFn func(rows *sql.Rows) (T, error)) ([]T, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", errLabel, err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.WarnContext(ctx, "failed to close rows", "error", cerr)
		}
	}()

	var results []T
	for rows.Next() {
		item, err := scanFn(rows)
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", errLabel, err)
		}
		results = append(results, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error %s: %w", errLabel, err)
	}
	return ic.EnsureSlice(results), nil
}

// enqueuePeerChange is the single shared helper for store-level peer-change
// fan-out via the ChangeWorker. PolicyStore and ServiceStore embed
// PeerChangeSupport (which delegates here) so the nil-worker and empty-ids
// guards live in exactly one place and cannot diverge. Synchronous queue
// failures (nil worker, stopped/full fallback errors) are returned so
// handlers fail the request instead of acking success with a lost signal;
// nil means the change was accepted for background persistence.
func enqueuePeerChange(ctx context.Context, changeWorker *change.ChangeWorker, peerIDs []int, changeType, changeAction string, changeID int, summary string) error {
	if changeWorker == nil {
		log.WarnContext(ctx, "dropping peer change: change worker is nil", "change_type", changeType, "change_action", changeAction, "change_id", changeID)
		return fmt.Errorf("cannot queue %s %s %d: change worker is nil", changeType, changeAction, changeID)
	}
	if len(peerIDs) == 0 {
		// Intentional silence would hide fan-out gaps, so log at debug
		// level (consistent with the warn above for the nil-worker path:
		// both paths are now observable, at different severities).
		log.DebugContext(ctx, "skipping peer change: no peers affected", "change_type", changeType, "change_action", changeAction, "change_id", changeID)
		return nil
	}
	return changeWorker.QueuePeerChange(ctx, peerIDs, changeType, changeAction, changeID, summary)
}

// PeerChangeSupport is embedded by stores that need to fan out peer changes
// via the ChangeWorker. The QueuePeerChange method is promoted, so callers
// keep calling store.QueuePeerChange while the implementation lives in
// exactly one place (enqueuePeerChange above) instead of being duplicated
// per store.
type PeerChangeSupport struct{}

// QueuePeerChange enqueues a peer change notification for the given peer IDs via the ChangeWorker.
// It returns synchronous queue failures so callers fail the request; nil
// means the change was accepted for background persistence.
func (PeerChangeSupport) QueuePeerChange(ctx context.Context, changeWorker *change.ChangeWorker, peerIDs []int, changeType, changeAction string, changeID int, summary string) error {
	return enqueuePeerChange(ctx, changeWorker, peerIDs, changeType, changeAction, changeID, summary)
}
