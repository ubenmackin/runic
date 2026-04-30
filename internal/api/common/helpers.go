// Package common provides shared utilities and constants.
package common

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// RespondJSON responds with JSON data.
func RespondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to encode json response", "error", err)
	}
}

// RespondError responds with a JSON error.
func RespondError(w http.ResponseWriter, status int, msg string) {
	RespondJSON(w, status, map[string]string{"error": msg})
}

// ParseIDParam parses an integer ID from mux variables.
func ParseIDParam(r *http.Request, name string) (int, error) {
	vars := mux.Vars(r)
	return strconv.Atoi(vars[name])
}

// ParseUintSafe parses a string as a uint64.
func ParseUintSafe(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}
