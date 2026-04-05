package common

import (
	"errors"
	"fmt"
)

// ErrUnauthorized is returned when an HTTP request receives a 401 Unauthorized response.
// This error signals that the agent should re-register with the control plane.
var ErrUnauthorized = errors.New("unauthorized: received 401 response")

// IsUnauthorized checks if an error is or wraps ErrUnauthorized.
func IsUnauthorized(err error) bool {
	return errors.Is(err, ErrUnauthorized)
}

// HTTPStatusError represents an HTTP response with a non-2xx status code.
type HTTPStatusError struct {
	StatusCode int
	Method     string
	URL        string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP %d %s %s", e.StatusCode, e.Method, e.URL)
}

func (e *HTTPStatusError) Is(target error) bool {
	if target == ErrUnauthorized && e.StatusCode == 401 {
		return true
	}
	return false
}
