package common

import (
	"errors"
	"fmt"
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
