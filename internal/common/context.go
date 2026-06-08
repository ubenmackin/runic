// Package common provides shared utilities.
package common

import (
	"context"
	"time"

	"runic/internal/common/constants"
)

// WithHandlerTimeout returns a context with a HandlerTimeout deadline. If the
// parent context already has a deadline at least as far in the future as
// HandlerTimeout, the parent is returned unchanged and the returned cancel
// function is a no-op. The caller must always invoke the returned cancel
// function to release resources.
func WithHandlerTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok {
		if time.Until(deadline) >= constants.HandlerTimeout {
			return ctx, func() {}
		}
	}
	return context.WithTimeout(ctx, constants.HandlerTimeout)
}
