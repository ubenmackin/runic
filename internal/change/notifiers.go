package change

// NotifyOutcome distinguishes why a bundle-update notification did or did
// not reach the agent. NotConnected means no SSE client is registered for
// the host; ChannelFull means a client is registered but its channel was
// full (backpressure, retryable). Callers must not map ChannelFull to
// not_connected.
//
// This type lives in the low-level change package so both the push worker
// (via BundleNotifier) and the SSE hub (internal/api/events) share one
// definition without the change package importing the API layer.
type NotifyOutcome int

const (
	// NotifySent means the notification was delivered.
	NotifySent NotifyOutcome = iota
	// NotifyNotConnected means no SSE client is registered for the host.
	NotifyNotConnected
	// NotifyChannelFull means a client is registered but its channel was
	// full (backpressure, retryable).
	NotifyChannelFull
)

// String returns the stable per-peer outcome key for a NotifyOutcome.
func (o NotifyOutcome) String() string {
	switch o {
	case NotifySent:
		return "sent"
	case NotifyNotConnected:
		return "not_connected"
	case NotifyChannelFull:
		return "channel_full"
	default:
		return "unknown"
	}
}

// Sent reports whether the notification was delivered.
func (o NotifyOutcome) Sent() bool {
	return o == NotifySent
}

// PendingChangeNotifier is the narrow SSE fan-out surface needed by the
// change worker. Depending on this interface instead of a concrete hub
// keeps the worker testable.
type PendingChangeNotifier interface {
	NotifyPendingChangeAdded(hostID string, peerID int)
	NotifyFrontendPendingChangeAdded(peerID int)
}

// BundleNotifier is the narrow SSE fan-out surface needed by the push
// worker. Depending on this interface instead of a concrete hub keeps the
// worker testable and decoupled from the hub implementation.
type BundleNotifier interface {
	NotifyBundleUpdated(hostID string, version string) NotifyOutcome
	NotifyPushJobProgress(jobID string, eventType string, payload string)
}
