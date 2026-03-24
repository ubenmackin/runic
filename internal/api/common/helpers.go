package common

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// RespondJSON responds with JSON data.
func RespondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
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
