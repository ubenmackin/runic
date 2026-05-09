package common

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
)

// A ResponseRecorder wraps an http.ResponseWriter to capture the status code.
// It implements http.ResponseWriter and http.Flusher for SSE streaming support.
type ResponseRecorder struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func NewResponseRecorder(w http.ResponseWriter) *ResponseRecorder {
	return &ResponseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

func (rw *ResponseRecorder) StatusCode() int {
	return rw.statusCode
}

func (rw *ResponseRecorder) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.ResponseWriter.WriteHeader(code)
		rw.written = true
	}
}

func (rw *ResponseRecorder) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

func (rw *ResponseRecorder) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rw *ResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("ResponseRecorder: underlying ResponseWriter does not implement http.Hijacker")
}
