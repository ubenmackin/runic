package engine

import (
	"context"
	"database/sql"

	"runic/internal/db"
)

// NewTestCompiler creates a Compiler with DB-backed lookup functions for testing.
// This avoids requiring the full store layer in unit tests while ensuring the
// Compiler always receives non-nil lookups as required by its constructor.
func NewTestCompiler(database *sql.DB) *Compiler {
	c := NewCompiler(database, testHostnameLookup(database), testGroupNameLookup(database))
	c.SetBeginner(database)
	return c
}

// testHostnameLookup creates a PeerHostnameLookup backed by direct DB queries for testing.
func testHostnameLookup(database db.Querier) PeerHostnameLookup {
	return func(ctx context.Context, peerID int) (string, error) {
		var hostname string
		err := database.QueryRowContext(ctx, "SELECT hostname FROM peers WHERE id = ?", peerID).Scan(&hostname)
		return hostname, err
	}
}

// testGroupNameLookup creates a GroupNameLookup backed by direct DB queries for testing.
func testGroupNameLookup(database db.Querier) GroupNameLookup {
	return func(ctx context.Context, groupID int) (string, error) {
		var name string
		err := database.QueryRowContext(ctx, "SELECT name FROM groups WHERE id = ? AND is_pending_delete = 0", groupID).Scan(&name)
		return name, err
	}
}
