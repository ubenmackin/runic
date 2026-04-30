package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if cErr := resp.Body.Close(); cErr != nil {
			slog.Warn("close body failed", "error", cErr)
		}
		httpErr := &HTTPStatusError{
			StatusCode: resp.StatusCode,
			Method:     method,
			URL:        url,
		}
		return nil, fmt.Errorf("request failed: %w", httpErr)
	}

	return resp, nil
}
