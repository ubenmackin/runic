// Package signal provides helpers for OS signal handling during graceful shutdown.
package signal

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var (
	// shutdownCh memoizes the channel returned by ShutdownSignal so that
	// repeated callers observe the same channel and the signal.Notify
	// registration happens exactly once per process. Without this, each
	// caller would register its own listener, and the global signal
	// disposition could be reset unexpectedly (e.g. by signal.Reset).
	shutdownCh   chan os.Signal
	shutdownOnce sync.Once
)

// ShutdownSignal returns a channel that receives OS shutdown signals
// (SIGINT, SIGTERM). The first call registers the signal handlers; subsequent
// calls return the same channel without re-registering.
func ShutdownSignal() <-chan os.Signal {
	shutdownOnce.Do(func() {
		ch := make(chan os.Signal, 2)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		shutdownCh = ch
	})
	return shutdownCh
}

// ResetSignalHandling removes OS-level signal handlers for SIGINT and SIGTERM
// previously installed via signal.Notify. This is typically called during
// graceful shutdown so that subsequent signals (e.g. a second Ctrl-C) terminate
// the process immediately using the default behavior.
//
// Note: the memoized shutdown channel returned by an earlier ShutdownSignal call
// remains valid, but will never receive a signal after this call because the
// underlying OS handler has been removed. Re-calling ShutdownSignal after this
// will return the same channel (also idle).
func ResetSignalHandling() {
	signal.Reset(syscall.SIGINT, syscall.SIGTERM)
}
