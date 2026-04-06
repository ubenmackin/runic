package common

import (
	"context"
	"testing"
	"time"
)

// TestWithHandlerTimeout_Deadline tests that WithHandlerTimeout returns a context
// with a deadline approximately 5 seconds in the future.
func TestWithHandlerTimeout_Deadline(t *testing.T) {
	ctx := context.Background()

	start := time.Now()
	ctxWithTimeout, cancel := WithHandlerTimeout(ctx)
	defer cancel()

	// Verify the context has a deadline
	deadline, hasDeadline := ctxWithTimeout.Deadline()
	if !hasDeadline {
		t.Fatal("WithHandlerTimeout() context should have a deadline")
	}

	// Verify the deadline is approximately 5 seconds from now
	elapsed := deadline.Sub(start)
	if elapsed < 4900*time.Millisecond || elapsed > 5100*time.Millisecond {
		t.Errorf("WithHandlerTimeout() timeout duration = %v, want approximately 5s", elapsed)
	}
}

// TestWithHandlerTimeout_CancelFunction tests that the cancel function properly releases resources
func TestWithHandlerTimeout_CancelFunction(t *testing.T) {
	ctx := context.Background()

	ctxWithTimeout, cancel := WithHandlerTimeout(ctx)

	// Cancel immediately
	cancel()

	// Verify context is cancelled
	select {
	case <-ctxWithTimeout.Done():
		// Good - context was cancelled
	default:
		t.Error("WithHandlerTimeout() context should be cancelled after cancel() is called")
	}

	// The error should be context.Canceled, not context.DeadlineExceeded
	if ctxWithTimeout.Err() != context.Canceled {
		t.Errorf("WithHandlerTimeout() error = %v, want context.Canceled", ctxWithTimeout.Err())
	}
}

// TestWithHandlerTimeout_NilParentContext tests handling with nil parent (uses Background)
func TestWithHandlerTimeout_NilParentContext(t *testing.T) {
	// In Go, context.Background() is used when nil is passed
	// The standard library handles this, but we use Background() explicitly
	ctx, cancel := WithHandlerTimeout(context.Background())
	defer cancel()

	if ctx == nil {
		t.Error("WithHandlerTimeout() returned nil context")
	}

	_, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		t.Error("WithHandlerTimeout() should set a deadline on Background context")
	}
}

// TestWithHandlerTimeout_CancelledParentContext tests that cancelled parent propagates
func TestWithHandlerTimeout_CancelledParentContext(t *testing.T) {
	parentCtx, parentCancel := context.WithCancel(context.Background())
	parentCancel() // Cancel parent immediately

	// Create child context from cancelled parent
	childCtx, childCancel := WithHandlerTimeout(parentCtx)
	defer childCancel()

	// Child should be cancelled because parent is cancelled
	select {
	case <-childCtx.Done():
		// Good - child was cancelled
		if childCtx.Err() != context.Canceled {
			t.Errorf("child context error = %v, want context.Canceled", childCtx.Err())
		}
	default:
		t.Error("child context should be cancelled when parent is cancelled")
	}
}

// TestWithHandlerTimeout_MultipleCalls tests multiple independent context creations
func TestWithHandlerTimeout_MultipleCalls(t *testing.T) {
	ctx1, cancel1 := WithHandlerTimeout(context.Background())
	defer cancel1()

	ctx2, cancel2 := WithHandlerTimeout(context.Background())
	defer cancel2()

	// Verify both have deadlines
	_, hasDeadline1 := ctx1.Deadline()
	_, hasDeadline2 := ctx2.Deadline()

	if !hasDeadline1 {
		t.Error("first context should have a deadline")
	}
	if !hasDeadline2 {
		t.Error("second context should have a deadline")
	}

	// Cancel only first context
	cancel1()

	// First should be cancelled, second should still be valid
	select {
	case <-ctx1.Done():
		// Good
	default:
		t.Error("first context should be cancelled")
	}

	select {
	case <-ctx2.Done():
		t.Error("second context should not be cancelled yet")
	default:
		// Good - second context is still valid
	}
}

// TestWithHandlerTimeout_ChainedContexts tests creating timeout from context with existing deadline
func TestWithHandlerTimeout_ChainedContexts(t *testing.T) {
	// Create parent with 10 second timeout
	parentCtx, parentCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer parentCancel()

	// Create child with 5 second timeout via WithHandlerTimeout
	childCtx, childCancel := WithHandlerTimeout(parentCtx)
	defer childCancel()

	// Child should inherit the shorter deadline (5s)
	// context.WithTimeout uses the earlier deadline when parent already has one
	parentDeadline, _ := parentCtx.Deadline()
	childDeadline, _ := childCtx.Deadline()

	// Child deadline should be earlier than or equal to parent
	if childDeadline.After(parentDeadline) {
		t.Errorf("child deadline %v should not be after parent deadline %v", childDeadline, parentDeadline)
	}
}
