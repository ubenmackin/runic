// Package common provides shared utilities.
package common

import (
	"context"
	"time"
)

// WithHandlerTimeout returns a context with a 5-second timeout, suitable for HTTP handler operations.
// The caller must call the returned cancel function to release resources.
func WithHandlerTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 5*time.Second)
}
