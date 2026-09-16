package common

import (
	"errors"
	"fmt"
	"time"
)

// ErrUnauthorized signals that the agent should re-register with the control plane.
var ErrUnauthorized = errors.New("unauthorized: received 401 response")

func IsUnauthorized(err error) bool {
	return errors.Is(err, ErrUnauthorized)
}

type HTTPStatusError struct {
	StatusCode int
	Method     string
	URL        string
	// RetryAfter is the parsed Retry-After delay for non-2xx responses.
	// Zero when the header was missing, unparseable, or explicitly zero.
	RetryAfter time.Duration
	// HasRetryAfter reports whether a Retry-After header was present and
	// parseable (delta-seconds or HTTP-date). A present "0", negative
	// delta, or past date yields RetryAfter==0 with HasRetryAfter==true
	// so callers can treat it as an immediate retry instead of falling
	// back to default backoff. Missing or unparseable headers yield false.
	HasRetryAfter bool
	// Body holds the truncated (4KB limit) response body snippet captured
	// on non-2xx responses for diagnostics.
	Body string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP %d %s %s", e.StatusCode, e.Method, e.URL)
}

// Is reports whether the receiver matches target. It matches ErrUnauthorized
// if and only if the receiver's StatusCode is 401. All other status codes
// (including 403 Forbidden) and all other target errors return false.
func (e *HTTPStatusError) Is(target error) bool {
	if target == ErrUnauthorized && e.StatusCode == 401 {
		return true
	}
	return false
}

// IsRateLimited reports whether err wraps an *HTTPStatusError with status
// code 429 (Too Many Requests).
func IsRateLimited(err error) bool {
	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode == 429
	}
	return false
}

// RetryAfterOf extracts the parsed Retry-After delay from err when it wraps
// an *HTTPStatusError carrying a present and parseable Retry-After header.
// Missing or unparseable headers yield (0, false). A present "0", negative
// delta-seconds, or past HTTP-date yields (0, true) meaning an immediate
// retry is allowed. Retry-After parsers clamp such values to 0 at
// construction, so a non-positive delay carries no additional wait and
// HasRetryAfter alone decides presence. A positive RetryAfter without
// HasRetryAfter reports (duration, false) so manually constructed errors
// cannot claim a hint that was never present.
func RetryAfterOf(err error) (time.Duration, bool) {
	var httpErr *HTTPStatusError
	if !errors.As(err, &httpErr) {
		return 0, false
	}
	if httpErr.RetryAfter <= 0 {
		return 0, httpErr.HasRetryAfter
	}
	return httpErr.RetryAfter, httpErr.HasRetryAfter
}
