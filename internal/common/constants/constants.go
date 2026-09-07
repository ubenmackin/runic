// Package constants provides shared configuration values used across the
// Runic server, agent, and shared libraries. All time-related values are
// expressed as time.Duration for consistency and type safety.
package constants

import "time"

// Agent timeouts and intervals control HTTP, SSE, and log transport behavior.
const (
	// HTTPClientTimeout is the maximum duration for outbound HTTP requests
	// made by the agent to the control plane.
	HTTPClientTimeout = 30 * time.Second

	// HandlerTimeout is the default per-request handler deadline applied by
	// common.WithHandlerTimeout when the incoming context has no shorter
	// deadline of its own.
	HandlerTimeout = 5 * time.Second

	// RevocationCheckTimeout caps how long the auth middleware will wait
	// for the token-revocation store to answer during request handling.
	RevocationCheckTimeout = 2 * time.Second

	// SmokeTestTimeout is the deadline for the post-apply smoke test that
	// verifies connectivity after a rule bundle change.
	SmokeTestTimeout = 10 * time.Second

	// ReachabilityTimeout is the maximum duration for the reachability check
	// performed before applying a new rule bundle.
	ReachabilityTimeout = 5 * time.Second

	// AutoRevertDelay is the grace period after an apply during which the
	// agent will automatically revert if the smoke test fails.
	AutoRevertDelay = 90 * time.Second

	// SSEKeepaliveInterval is how often the server sends keep-alive frames
	// over the Server-Sent Events connection to prevent idle timeouts.
	SSEKeepaliveInterval = 30 * time.Second

	// SSEReconnectDelay is the back-off duration before the agent attempts
	// to reconnect a dropped SSE stream.
	SSEReconnectDelay = 15 * time.Second

	// LogShipperBatchInterval is how often the log shipper flushes buffered
	// log entries to the control plane.
	LogShipperBatchInterval = 10 * time.Second

	// LogTailSleepInterval is the polling interval for the log tailer when
	// watching the firewall log file for new entries.
	LogTailSleepInterval = 500 * time.Millisecond
)

// Offline detection constants govern how the server determines peer liveness.
const (
	// OfflineThreshold is the duration without a heartbeat after which a
	// peer is considered offline. This value is used by the offline
	// detector background job, the dashboard SQL queries, and the
	// peer-listing status computation. It must be greater than the
	// agent's default heartbeat interval (30 s) to avoid false positives.
	OfflineThreshold = 90 * time.Second
)

// Network defaults shared by the server bootstrap and the policy compiler.
const (
	// DefaultControlPlanePort is the default HTTPS port for control plane
	// communication. The server listens on this port and the compiler emits
	// allow rules for it, so both must stay in sync through this constant.
	DefaultControlPlanePort = "60443"
)

// Cleanup intervals control periodic background maintenance tasks.
const (
	// RateLimitCleanupInterval is how often expired rate-limit entries
	// are pruned from the in-memory limiter.
	RateLimitCleanupInterval = 5 * time.Minute

	// AuthRateLimitCleanupInterval is how often expired auth-specific
	// rate-limit entries are pruned.
	AuthRateLimitCleanupInterval = 1 * time.Hour

	// OfflineDetectorInterval is how often the background job checks for
	// peers that have exceeded OfflineThreshold and marks them offline.
	OfflineDetectorInterval = 30 * time.Second

	// OfflineCleanupInterval is how often stale offline-peer records are
	// purged from the database.
	OfflineCleanupInterval = 1 * time.Hour

	// WebSocketPingInterval is how often the server sends WebSocket ping
	// frames to keep connections alive through intermediaries.
	WebSocketPingInterval = 54 * time.Second

	// ReadyHandlerTimeout caps how long the /ready endpoint will wait for
	// the database Ping before reporting "not ready".
	ReadyHandlerTimeout = 2 * time.Second
)
