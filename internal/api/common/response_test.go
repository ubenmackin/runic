package common

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNewResponseRecorder tests the constructor
func TestNewResponseRecorder(t *testing.T) {
	rec := httptest.NewRecorder()
	rr := NewResponseRecorder(rec)

	if rr == nil {
		t.Fatal("NewResponseRecorder() returned nil")
	}

	// Should have the underlying ResponseWriter set
	if rr.ResponseWriter == nil {
		t.Error("NewResponseRecorder() ResponseWriter is nil")
	}
}

// TestResponseRecorder_StatusCode tests StatusCode retrieval
func TestResponseRecorder_StatusCode(t *testing.T) {
	tests := []struct {
		name       string
		setStatus  func(*ResponseRecorder)
		wantStatus int
	}{
		{
			name:       "default status code is 200",
			setStatus:  nil,
			wantStatus: http.StatusOK,
		},
		{
			name: "status code set via WriteHeader",
			setStatus: func(rr *ResponseRecorder) {
				rr.WriteHeader(http.StatusCreated)
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "status code set to 404",
			setStatus: func(rr *ResponseRecorder) {
				rr.WriteHeader(http.StatusNotFound)
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "status code set to 500",
			setStatus: func(rr *ResponseRecorder) {
				rr.WriteHeader(http.StatusInternalServerError)
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			rr := NewResponseRecorder(rec)

			if tt.setStatus != nil {
				tt.setStatus(rr)
			}

			got := rr.StatusCode()
			if got != tt.wantStatus {
				t.Errorf("StatusCode() = %d, want %d", got, tt.wantStatus)
			}
		})
	}
}

// TestResponseRecorder_WriteHeader tests WriteHeader behavior
func TestResponseRecorder_WriteHeader(t *testing.T) {
	t.Run("delegates to underlying ResponseWriter", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rr := NewResponseRecorder(rec)

		rr.WriteHeader(http.StatusCreated)

		// Should also write to underlying ResponseWriter
		if rec.Code != http.StatusCreated {
			t.Errorf("underlying recorder.Code = %d, want %d", rec.Code, http.StatusCreated)
		}
	})

	t.Run("does not overwrite status code on second call", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rr := NewResponseRecorder(rec)

		// First WriteHeader
		rr.WriteHeader(http.StatusCreated)

		// Second WriteHeader - should be ignored
		rr.WriteHeader(http.StatusBadRequest)

		// Should keep the first status code
		if got := rr.StatusCode(); got != http.StatusCreated {
			t.Errorf("StatusCode() = %d, want %d (first status should be kept)", got, http.StatusCreated)
		}
	})

	t.Run("written flag prevents double write", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rr := NewResponseRecorder(rec)

		rr.WriteHeader(http.StatusAccepted)

		// Check written flag was set
		if !rr.written {
			t.Error("written flag should be true after WriteHeader")
		}

		// Second call should not change status
		rr.WriteHeader(http.StatusBadGateway)

		if rr.StatusCode() != http.StatusAccepted {
			t.Errorf("StatusCode() changed after second WriteHeader, got %d, want %d", rr.StatusCode(), http.StatusAccepted)
		}
	})
}

// TestResponseRecorder_Write tests Write behavior
func TestResponseRecorder_Write(t *testing.T) {
	t.Run("calls WriteHeader with 200 if not already written", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rr := NewResponseRecorder(rec)

		body := []byte("test body")
		n, err := rr.Write(body)

		if err != nil {
			t.Errorf("Write() error = %v", err)
		}
		if n != len(body) {
			t.Errorf("Write() = %d, want %d", n, len(body))
		}

		// Should have set status code to 200
		if rr.StatusCode() != http.StatusOK {
			t.Errorf("StatusCode() = %d, want %d", rr.StatusCode(), http.StatusOK)
		}

		// Body should be written to underlying recorder
		if rec.Body.String() != "test body" {
			t.Errorf("Body = %q, want %q", rec.Body.String(), "test body")
		}
	})

	t.Run("does not overwrite status code if already written", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rr := NewResponseRecorder(rec)

		// Set status code first
		rr.WriteHeader(http.StatusNotFound)

		// Now write body
		_, _ = rr.Write([]byte("error body"))

		// Status should remain 404, not change to 200
		if rr.StatusCode() != http.StatusNotFound {
			t.Errorf("StatusCode() = %d, want %d", rr.StatusCode(), http.StatusNotFound)
		}
	})

	t.Run("Write returns bytes written", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rr := NewResponseRecorder(rec)

		body := []byte("hello world")
		n, err := rr.Write(body)

		if err != nil {
			t.Errorf("Write() error = %v", err)
		}
		if n != len(body) {
			t.Errorf("Write() = %d bytes, want %d", n, len(body))
		}
	})

}

// TestResponseRecorder_Flush tests Flush behavior
func TestResponseRecorder_Flush(t *testing.T) {
	t.Run("delegates to underlying Flusher when available", func(t *testing.T) {
		// httptest.ResponseRecorder implements Flusher
		rec := httptest.NewRecorder()
		rr := NewResponseRecorder(rec)

		// Should not panic when Flush is called
		rr.Flush()
		// No assertion needed - just verify it doesn't panic
	})

	t.Run("does not panic when underlying ResponseWriter does not implement Flusher", func(t *testing.T) {
		// Create a minimal ResponseWriter that does NOT implement Flusher
		rec := &mockResponseWriter{}
		rr := NewResponseRecorder(rec)

		// Should not panic
		rr.Flush()
		// No assertion needed - just verify it doesn't panic
	})
}

// TestResponseRecorder_Integration tests with real HTTP handler
func TestResponseRecorder_Integration(t *testing.T) {
	t.Run("captures status code from HTTP handler and writes body", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rr := NewResponseRecorder(rec)

		// Simulate a handler that sets a specific status and writes body
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		})

		req := httptest.NewRequest(http.MethodGet, "/missing", nil)
		handler(rr, req)

		// Verify status code was captured
		if rr.StatusCode() != http.StatusNotFound {
			t.Errorf("StatusCode() = %d, want %d", rr.StatusCode(), http.StatusNotFound)
		}

		// Verify body was written
		if rec.Body.String() != "not found" {
			t.Errorf("Body = %q, want %q", rec.Body.String(), "not found")
		}
	})

	t.Run("handler writes body without explicit status uses default 200", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rr := NewResponseRecorder(rec)

		// Handler that writes body but doesn't set status (implicitly 200)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok"))
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		handler(rr, req)

		// Should default to 200
		if rr.StatusCode() != http.StatusOK {
			t.Errorf("StatusCode() = %d, want %d", rr.StatusCode(), http.StatusOK)
		}

		// Verify body was written
		if rec.Body.String() != "ok" {
			t.Errorf("Body = %q, want %q", rec.Body.String(), "ok")
		}
	})

	t.Run("multiple Write calls only set status once", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rr := NewResponseRecorder(rec)

		// First write sets status to 200
		_, _ = rr.Write([]byte("part1"))

		// Status should now be locked to 200
		if rr.StatusCode() != http.StatusOK {
			t.Errorf("StatusCode() after first write = %d, want %d", rr.StatusCode(), http.StatusOK)
		}

		// Second write should not change status
		_, _ = rr.Write([]byte("part2"))

		if rr.StatusCode() != http.StatusOK {
			t.Errorf("StatusCode() after second write = %d, want %d", rr.StatusCode(), http.StatusOK)
		}

		// Verify body accumulated
		if rec.Body.String() != "part1part2" {
			t.Errorf("Body = %q, want %q", rec.Body.String(), "part1part2")
		}
	})
}

// mockResponseWriter is a minimal mock that does NOT implement http.Flusher
type mockResponseWriter struct{}

func (m *mockResponseWriter) Header() http.Header {
	return http.Header{}
}

func (m *mockResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {}
