package common

import "net/http"

// HTTPClient is the interface for HTTP clients.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}
