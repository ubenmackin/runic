// Package common provides shared utilities.
package common

import (
	"context"
	"time"
)

// WithHandlerTimeout returns a context with a 5-second timeout, suitable for HTTP handler operations.
// If the context already has a deadline >= 5 seconds, it is used as-is.
// The caller must call the returned cancel function to release resources.
func WithHandlerTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok {
		if time.Until(deadline) >= 5*time.Second {
			return ctx, func() {}
		}
	}
	return context.WithTimeout(ctx, 5*time.Second)
}
