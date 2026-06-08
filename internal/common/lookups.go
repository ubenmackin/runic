package common

import "context"

// PeerHostnameLookup retrieves a peer hostname by ID.
// Returns ("", sql.ErrNoRows) if not found.
//
// Cross-package contract: implementations are constructed in higher-level
// packages (e.g. internal/alerts) that own the peer store, and are passed
// into common-package helpers that need hostname resolution without
// importing the peer store directly. This keeps common free of database
// dependencies.
type PeerHostnameLookup func(ctx context.Context, peerID int) (string, error)
