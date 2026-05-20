// Package signal provides helpers for OS signal handling during graceful shutdown.
package signal

import (
	"os"
	"os/signal"
	"syscall"
)

// ShutdownSignal returns a channel that receives OS shutdown signals (SIGINT, SIGTERM).
// The channel has buffer size 2 to prevent lost signals during shutdown.
func ShutdownSignal() <-chan os.Signal {
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	return sigCh
}

// ResetSignalHandling resets signal handling (call after shutdown begins to prevent double-kill).
func ResetSignalHandling() {
	signal.Reset(syscall.SIGINT, syscall.SIGTERM)
}
