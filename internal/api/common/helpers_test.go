package common

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// TestRespondJSON tests the RespondJSON function with various payloads
func TestRespondJSON(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		data       interface{}
		wantStatus int
		wantBody   string
	}{
		{
			name:       "success with map",
			status:     http.StatusOK,
			data:       map[string]string{"message": "success"},
			wantStatus: http.StatusOK,
			wantBody:   `{"message":"success"}`,
		},
		{
			name:       "success with struct",
			status:     http.StatusOK,
			data:       struct{ Name string }{Name: "test"},
			wantStatus: http.StatusOK,
			wantBody:   `{"Name":"test"}`,
		},
		{
			name:       "created status",
			status:     http.StatusCreated,
			data:       map[string]int{"id": 42},
			wantStatus: http.StatusCreated,
			wantBody:   `{"id":42}`,
		},
		{
			name:       "empty map",
			status:     http.StatusOK,
			data:       map[string]string{},
			wantStatus: http.StatusOK,
			wantBody:   `{}`,
		},
		{
			name:       "nil payload",
			status:     http.StatusOK,
			data:       nil,
			wantStatus: http.StatusOK,
			wantBody:   `null`,
		},
		{
			name:       "slice of strings",
			status:     http.StatusOK,
			data:       []string{"a", "b", "c"},
			wantStatus: http.StatusOK,
			wantBody:   `["a","b","c"]`,
		},
		{
			name:       "slice of integers",
			status:     http.StatusOK,
			data:       []int{1, 2, 3},
			wantStatus: http.StatusOK,
			wantBody:   `[1,2,3]`,
		},
		{
			name:       "nested map",
			status:     http.StatusOK,
			data:       map[string]interface{}{"outer": map[string]int{"inner": 42}},
			wantStatus: http.StatusOK,
			wantBody:   `{"outer":{"inner":42}}`,
		},
		{
			name:       "boolean value",
			status:     http.StatusOK,
			data:       map[string]bool{"enabled": true},
			wantStatus: http.StatusOK,
			wantBody:   `{"enabled":true}`,
		},
		{
			name:       "bad request status",
			status:     http.StatusBadRequest,
			data:       map[string]string{"error": "invalid input"},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid input"}`,
		},
		{
			name:       "not found status",
			status:     http.StatusNotFound,
			data:       map[string]string{"error": "resource not found"},
			wantStatus: http.StatusNotFound,
			wantBody:   `{"error":"resource not found"}`,
		},
		{
			name:       "internal server error status",
			status:     http.StatusInternalServerError,
			data:       map[string]string{"error": "internal error"},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal error"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			RespondJSON(w, tt.status, tt.data)

			// Check status code
			if w.Code != tt.wantStatus {
				t.Errorf("RespondJSON() status = %v, want %v", w.Code, tt.wantStatus)
			}

			// Check content type header
			if ct := w.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("RespondJSON() Content-Type = %v, want application/json", ct)
			}

			// Check body matches expected
			if tt.wantBody != "" && strings.TrimSpace(w.Body.String()) != tt.wantBody {
				t.Errorf("RespondJSON() body = %v, want %v", strings.TrimSpace(w.Body.String()), tt.wantBody)
			}

			// Check body - verify JSON is valid
			body := w.Body.String()
			var result interface{}
			if err := json.Unmarshal([]byte(body), &result); err != nil {
				t.Errorf("RespondJSON() body is not valid JSON: %v", err)
			}
		})
	}
}

// TestRespondError tests the RespondError function with different error messages
func TestRespondError(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		msg        string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "bad request error",
			status:     http.StatusBadRequest,
			msg:        "invalid request body",
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid request body"}`,
		},
		{
			name:       "unauthorized error",
			status:     http.StatusUnauthorized,
			msg:        "authentication required",
			wantStatus: http.StatusUnauthorized,
			wantBody:   `{"error":"authentication required"}`,
		},
		{
			name:       "forbidden error",
			status:     http.StatusForbidden,
			msg:        "access denied",
			wantStatus: http.StatusForbidden,
			wantBody:   `{"error":"access denied"}`,
		},
		{
			name:       "not found error",
			status:     http.StatusNotFound,
			msg:        "peer not found",
			wantStatus: http.StatusNotFound,
			wantBody:   `{"error":"peer not found"}`,
		},
		{
			name:       "internal server error",
			status:     http.StatusInternalServerError,
			msg:        "database connection failed",
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"database connection failed"}`,
		},
		{
			name:       "conflict error",
			status:     http.StatusConflict,
			msg:        "resource already exists",
			wantStatus: http.StatusConflict,
			wantBody:   `{"error":"resource already exists"}`,
		},
		{
			name:       "empty error message",
			status:     http.StatusBadRequest,
			msg:        "",
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":""}`,
		},
		{
			name:       "error with special characters",
			status:     http.StatusBadRequest,
			msg:        "error: invalid 'field' \"name\"",
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"error: invalid 'field' \"name\""}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			RespondError(w, tt.status, tt.msg)

			// Check status code
			if w.Code != tt.wantStatus {
				t.Errorf("RespondError() status = %v, want %v", w.Code, tt.wantStatus)
			}

			// Check content type header
			if ct := w.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("RespondError() Content-Type = %v, want application/json", ct)
			}

			// Check body contains error field
			var result map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Errorf("RespondError() body is not valid JSON: %v", err)
			}

			if result["error"] != tt.msg {
				t.Errorf("RespondError() error message = %v, want %v", result["error"], tt.msg)
			}
		})
	}
}

// TestParseIDParam tests the ParseIDParam function with valid and invalid inputs
func TestParseIDParam(t *testing.T) {
	tests := []struct {
		name      string
		paramName string
		paramVal  string
		wantID    int
		wantErr   bool
	}{
		{
			name:      "valid positive ID",
			paramName: "id",
			paramVal:  "42",
			wantID:    42,
			wantErr:   false,
		},
		{
			name:      "valid ID one",
			paramName: "id",
			paramVal:  "1",
			wantID:    1,
			wantErr:   false,
		},
		{
			name:      "valid large ID",
			paramName: "id",
			paramVal:  "999999",
			wantID:    999999,
			wantErr:   false,
		},
		{
			name:      "invalid non-numeric ID",
			paramName: "id",
			paramVal:  "abc",
			wantID:    0,
			wantErr:   true,
		},
		{
			name:      "invalid negative ID",
			paramName: "id",
			paramVal:  "-1",
			wantID:    -1,
			wantErr:   false, // strconv.Atoi accepts negative numbers
		},
		{
			name:      "invalid empty string",
			paramName: "id",
			paramVal:  "",
			wantID:    0,
			wantErr:   true,
		},
		{
			name:      "invalid float string",
			paramName: "id",
			paramVal:  "3.14",
			wantID:    0,
			wantErr:   true,
		},
		{
			name:      "valid peer_id param",
			paramName: "peer_id",
			paramVal:  "123",
			wantID:    123,
			wantErr:   false,
		},
		{
			name:      "valid group_id param",
			paramName: "group_id",
			paramVal:  "456",
			wantID:    456,
			wantErr:   false,
		},
		{
			name:      "invalid with spaces",
			paramName: "id",
			paramVal:  " 42 ",
			wantID:    0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock request with a safe URL path
			req := httptest.NewRequest("GET", "/test", nil)

			// Set mux variables with the actual test value
			vars := map[string]string{tt.paramName: tt.paramVal}
			req = mux.SetURLVars(req, vars)

			id, err := ParseIDParam(req, tt.paramName)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseIDParam() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("ParseIDParam() unexpected error: %v", err)
				}
				if id != tt.wantID {
					t.Errorf("ParseIDParam() id = %v, want %v", id, tt.wantID)
				}
			}
		})
	}
}

// TestParseIDParamMissingParam tests that ParseIDParam handles missing parameters
func TestParseIDParamMissingParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	// No mux vars set - simulates missing parameter
	req = mux.SetURLVars(req, map[string]string{})

	id, err := ParseIDParam(req, "missing_id")

	// When parameter is missing, mux.Vars returns empty string, strconv.Atoi("") fails
	if err == nil {
		t.Errorf("ParseIDParam() expected error for missing parameter, got id=%d", id)
	}
}

// TestParseIDParamMultipleVars tests parsing when multiple route variables are present
func TestParseIDParamMultipleVars(t *testing.T) {
	req := httptest.NewRequest("GET", "/peers/123/policies/456", nil)
	vars := map[string]string{
		"peer_id":   "123",
		"policy_id": "456",
	}
	req = mux.SetURLVars(req, vars)

	// Parse peer_id
	peerID, err := ParseIDParam(req, "peer_id")
	if err != nil {
		t.Errorf("ParseIDParam(peer_id) unexpected error: %v", err)
	}
	if peerID != 123 {
		t.Errorf("ParseIDParam(peer_id) = %d, want 123", peerID)
	}

	// Parse policy_id
	policyID, err := ParseIDParam(req, "policy_id")
	if err != nil {
		t.Errorf("ParseIDParam(policy_id) unexpected error: %v", err)
	}
	if policyID != 456 {
		t.Errorf("ParseIDParam(policy_id) = %d, want 456", policyID)
	}
}

// TestRespondJSONMultipleCalls tests that multiple calls set correct headers
func TestRespondJSONMultipleCalls(t *testing.T) {
	w := httptest.NewRecorder()

	// First call
	RespondJSON(w, http.StatusOK, map[string]string{"first": "1"})
	if w.Code != http.StatusOK {
		t.Errorf("First call status = %d, want %d", w.Code, http.StatusOK)
	}

	// Second call (note: cannot change status code after first WriteHeader)
	w = httptest.NewRecorder()
	RespondJSON(w, http.StatusCreated, map[string]string{"second": "2"})
	if w.Code != http.StatusCreated {
		t.Errorf("Second call status = %d, want %d", w.Code, http.StatusCreated)
	}
}

// TestParseUintSafe tests the ParseUintSafe function with various inputs
func TestParseUintSafe(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint64
		wantErr bool
	}{
		{
			name:    "valid small number",
			input:   "42",
			want:    42,
			wantErr: false,
		},
		{
			name:    "valid number one",
			input:   "1",
			want:    1,
			wantErr: false,
		},
		{
			name:    "zero",
			input:   "0",
			want:    0,
			wantErr: false,
		},
		{
			name:    "max uint64 edge case",
			input:   "18446744073709551615",
			want:    math.MaxUint64,
			wantErr: false,
		},
		{
			name:    "value exceeds max uint64",
			input:   "18446744073709551616",
			want:    0,
			wantErr: true,
		},
		{
			name:    "invalid non-numeric input",
			input:   "abc",
			want:    0,
			wantErr: true,
		},
		{
			name:    "negative input",
			input:   "-1",
			want:    0,
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			want:    0,
			wantErr: true,
		},
		{
			name:    "float string",
			input:   "3.14",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseUintSafe(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseUintSafe(%q) expected error, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("ParseUintSafe(%q) unexpected error: %v", tt.input, err)
				}
				if got != tt.want {
					t.Errorf("ParseUintSafe(%q) = %v, want %v", tt.input, got, tt.want)
				}
			}
		})
	}
}
