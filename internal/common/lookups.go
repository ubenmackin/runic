package common

import "context"

// PeerHostnameLookup retrieves a peer hostname by ID. Returns ("", sql.ErrNoRows) if not found.
type PeerHostnameLookup func(ctx context.Context, peerID int) (string, error)
