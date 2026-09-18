// Package change provides the low-level pending-change fan-out primitives
// shared by the store layer and the API layer.
//
// It sits below internal/api in the dependency graph: both internal/store
// (DB layer) and internal/api/... (HTTP layer) import it, while it only
// depends on leaf packages (internal/engine, internal/db, internal/common).
// This keeps the layering intact (api depends on store, never the reverse)
// while giving both layers a single implementation of the change-worker
// contract, the pending-change notifiers, and the delete-constraint errors.
package change
