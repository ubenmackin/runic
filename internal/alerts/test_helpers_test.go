package alerts

import (
	"context"
	"database/sql"

	"runic/internal/common"
)

// newTestHostnameLookup creates a PeerHostnameLookup backed by direct DB queries for testing.
// This avoids requiring the full store layer in unit tests while ensuring the
// evaluator/detector always receives a non-nil lookup as required by their constructors.
// If database is nil, returns a lookup that always returns sql.ErrNoRows.
func newTestHostnameLookup(database *sql.DB) PeerHostnameLookup {
	if database == nil {
		return func(_ context.Context, _ int) (string, error) {
			return "", sql.ErrNoRows
		}
	}
	return common.PeerHostnameLookup(func(ctx context.Context, peerID int) (string, error) {
		var hostname string
		err := database.QueryRowContext(ctx, "SELECT hostname FROM peers WHERE id = ?", peerID).Scan(&hostname)
		return hostname, err
	})
}
