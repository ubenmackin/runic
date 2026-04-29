// Package common provides shared utilities and constants.
package common

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

// RespondJSON responds with JSON data.
func RespondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		fmt.Printf("failed to encode json response: %v\n", err)
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

// FormatSQLiteDatetime converts a SQLite datetime string (YYYY-MM-DD HH:MM:SS)
// to RFC 3339 format (YYYY-MM-DDTHH:MM:SSZ). SQLite's CURRENT_TIMESTAMP and
// datetime('now') produce UTC times without timezone info, so the parsed time
// is treated as UTC. If the string is empty, it returns an empty string.
// If the input is already in RFC 3339 format, it is returned unchanged.
// If parsing fails for both formats, the original string is returned unchanged.
func FormatSQLiteDatetime(s string) string {
	if s == "" {
		return ""
	}
	// Try SQLite datetime format first (YYYY-MM-DD HH:MM:SS)
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	// Already in RFC 3339 format — return as-is
	if _, err := time.Parse(time.RFC3339, s); err == nil {
		return s
	}
	// Unable to parse — return original string unchanged
	return s
}
