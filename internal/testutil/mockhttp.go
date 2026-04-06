package testutil

import (
	"net/http"
)

// MockHTTPClient implements the HTTPClient interface for testing
type MockHTTPClient struct {
	Resp *http.Response
	Err  error
}

// Do implements the HTTPClient interface
func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.Resp, m.Err
}
