package common

import (
	"database/sql"

	"runic/internal/change"
)

// PendingChangeNotifier is an alias for change.PendingChangeNotifier so
// existing API callers keep importing internal/api/common without change.
// The implementation lives in the low-level internal/change package so the
// store layer can depend on it without importing the API layer.
type PendingChangeNotifier = change.PendingChangeNotifier

// ChangeWorker is an alias for change.ChangeWorker. The implementation lives
// in internal/change (below internal/api) so internal/store can fan out
// pending changes without creating a store→api import inversion.
type ChangeWorker = change.ChangeWorker

// NewChangeWorker creates a change worker. It is a thin wrapper around
// change.NewChangeWorker kept for backward compatibility with API callers.
func NewChangeWorker(sseHub change.PendingChangeNotifier, database *sql.DB) *change.ChangeWorker {
	return change.NewChangeWorker(sseHub, database)
}
