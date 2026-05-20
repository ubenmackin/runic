// Package common provides shared utilities and constants.
package common

import (
	"fmt"
	"net/http"

	"runic/internal/common/log"
)

// InternalError responds with a generic 500 error. Detailed errors should be logged server-side before calling this function.
func InternalError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	if _, err := w.Write([]byte(`{"error": "internal server error"}`)); err != nil {
		log.Error("failed to write error response", "error", err)
	}
}

type HTTPError struct {
	StatusCode int
	Message    string
	Err        error
}

func (e *HTTPError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *HTTPError) Unwrap() error {
	return e.Err
}

func NewHTTPError(statusCode int, message string, errs ...error) *HTTPError {
	var err error
	if len(errs) > 0 {
		err = errs[0]
	}
	return &HTTPError{
		StatusCode: statusCode,
		Message:    message,
		Err:        err,
	}
}
