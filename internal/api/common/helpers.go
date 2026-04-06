// Package common provides shared utilities and constants.
package common

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

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
