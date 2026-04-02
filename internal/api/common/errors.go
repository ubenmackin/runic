package common

import "net/http"

// InternalError returns a generic 500 response to prevent information leakage.
// Detailed errors should be logged server-side before calling this function.
func InternalError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(`{"error": "internal server error"}`))
}
