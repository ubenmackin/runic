package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"runic/internal/common/log"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// DoJSONRequest sends an HTTP request with a JSON body. It sets Content-Type,
// User-Agent, and optional Authorization headers.
//
// The caller MUST close resp.Body on the returned response when finished
// reading from it. On non-2xx status codes the body is already drained and
// closed before an error is returned; on success the caller is responsible
// for closing resp.Body.
func DoJSONRequest(ctx context.Context, client HTTPClient, method, url string, body interface{}, token, userAgent string) (*http.Response, error) {
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
	}
	bodyReader := bytes.NewReader(data)

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
		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if cErr := resp.Body.Close(); cErr != nil {
			log.Warn("close body failed", "error", cErr)
		}
		httpErr := &HTTPStatusError{
			StatusCode: resp.StatusCode,
			Method:     method,
			URL:        url,
		}
		if readErr == nil {
			bodyStr := strings.TrimSpace(string(bodyBytes))
			if bodyStr != "" {
				return nil, fmt.Errorf("request failed: %w (body: %s)", httpErr, bodyStr)
			}
		}
		return nil, fmt.Errorf("request failed: %w", httpErr)
	}

	return resp, nil
}
