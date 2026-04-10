package common

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
)

// ResponseRecorder wraps http.ResponseWriter to capture the status code.
// It implements http.ResponseWriter and http.Flusher for SSE streaming support.
type ResponseRecorder struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// NewResponseRecorder creates a new ResponseRecorder wrapping the given ResponseWriter.
func NewResponseRecorder(w http.ResponseWriter) *ResponseRecorder {
	return &ResponseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

// StatusCode returns the captured status code.
func (rw *ResponseRecorder) StatusCode() int {
	return rw.statusCode
}

// WriteHeader captures the status code and calls the underlying WriteHeader.
func (rw *ResponseRecorder) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.ResponseWriter.WriteHeader(code)
		rw.written = true
	}
}

// Write ensures WriteHeader is called with default status if not already set.
func (rw *ResponseRecorder) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// Flush implements http.Flusher to support SSE streaming.
func (rw *ResponseRecorder) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker to support WebSocket upgrade.
func (rw *ResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("ResponseRecorder: underlying ResponseWriter does not implement http.Hijacker")
}
