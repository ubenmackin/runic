package constants

import "time"

// Agent timeouts
const (
	HTTPClientTimeout       = 30 * time.Second
	SmokeTestTimeout        = 10 * time.Second
	ReachabilityTimeout     = 5 * time.Second
	AutoRevertDelay         = 90 * time.Second
	SSEKeepaliveInterval    = 30 * time.Second
	SSEReconnectDelay       = 15 * time.Second
	LogShipperBatchInterval = 10 * time.Second
	LogTailSleepInterval    = 500 * time.Millisecond
)

// Offline detection
const (
	OfflineThresholdSeconds     = 90 // seconds without heartbeat = offline
	PeerOfflineThresholdMinutes = 2  // minutes without heartbeat = offline (for SQL datetime calculations)
)

// Cleanup intervals
const (
	RateLimitCleanupInterval     = 5 * time.Minute
	AuthRateLimitCleanupInterval = 1 * time.Hour
	OfflineDetectorInterval      = 30 * time.Second
	OfflineCleanupInterval       = 1 * time.Hour
	WebSocketPingInterval        = 54 * time.Second
)
