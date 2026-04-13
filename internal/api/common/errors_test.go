// Package common provides shared utilities and constants.
package common

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInternalError(t *testing.T) {
	w := httptest.NewRecorder()
	InternalError(w)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", w.Header().Get("Content-Type"))
	}

	expected := `{"error": "internal server error"}`
	if strings.TrimSpace(w.Body.String()) != expected {
		t.Errorf("expected body %s, got %s", expected, w.Body.String())
	}
}

func TestInternalErrorVerifyWrite(t *testing.T) {
	w := httptest.NewRecorder()
	InternalError(w)

	// Verify the response was written without errors
	// httptest.ResponseRecorder captures any write errors
	if w.Body.Len() == 0 {
		t.Error("expected response body to be written, but it was empty")
	}
}
