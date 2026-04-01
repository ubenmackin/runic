package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// HTTPClient is the interface for HTTP clients.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// DoJSONRequest sends a JSON request to the given URL with the provided body and token.
// It sets Content-Type, User-Agent, and optional Authorization headers.
func DoJSONRequest(ctx context.Context, client HTTPClient, method, url string, body interface{}, token, userAgent string) (*http.Response, error) {
	var bodyReader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	return client.Do(req)
}
