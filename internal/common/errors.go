package common

import "errors"

// ErrUnauthorized is returned when an HTTP request receives a 401 Unauthorized response.
// This error signals that the agent should re-register with the control plane.
var ErrUnauthorized = errors.New("unauthorized: received 401 response")

// IsUnauthorized checks if an error is or wraps ErrUnauthorized.
func IsUnauthorized(err error) bool {
	return errors.Is(err, ErrUnauthorized)
}
