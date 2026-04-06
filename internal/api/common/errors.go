// Package common provides shared utilities and constants.
package common

import (
	"log"
	"net/http"
)

// InternalError returns a generic 500 response to prevent information leakage.
// Detailed errors should be logged server-side before calling this function.
func InternalError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	if _, err := w.Write([]byte(`{"error": "internal server error"}`)); err != nil {
		log.Printf("failed to write error response: %v", err)
	}
}
