package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"runic/internal/common/log"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// ParseRetryAfter parses a Retry-After header value, which is either
// delta-seconds or an HTTP date. It returns 0 when the header is missing,
// unparseable, or in the past. It is the single canonical helper shared by
// DoJSONRequest, the agent transport puller, and the agent updater so
// Retry-After parsing cannot drift between paths.
func ParseRetryAfter(header string) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	if secs, err := strconv.Atoi(header); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := time.Parse(http.TimeFormat, header); err == nil {
		d := time.Until(t)
		if d < 0 {
			return 0
		}
		return d
	}
	return 0
}

// ParseRetryAfterPresent parses a Retry-After header value and reports
// whether the header was present and parseable. A present header with value
// "0" or a past date yields (0, true) so callers can honor it as an immediate
// retry instead of falling back to exponential backoff. Missing or
// unparseable headers yield (0, false). It is the single canonical helper
// shared by DoJSONRequest, the agent transport puller, and the agent updater.
func ParseRetryAfterPresent(header string) (time.Duration, bool) {
	trimmed := strings.TrimSpace(header)
	if trimmed == "" {
		return 0, false
	}
	d := ParseRetryAfter(trimmed)
	if d != 0 {
		return d, true
	}
	// d == 0: distinguish present-zero ("0", negative delta, past date)
	// from unparseable input.
	if _, err := strconv.Atoi(trimmed); err == nil {
		return 0, true
	}
	if _, err := time.Parse(http.TimeFormat, trimmed); err == nil {
		return 0, true
	}
	return 0, false
}

// NewHTTPStatusError builds an *HTTPStatusError from response details. It
// parses the Retry-After header via ParseRetryAfterPresent and trims the
// body snippet, ignoring the body when readErr is non-nil. It is the single
// canonical constructor shared by DoJSONRequest and the agent transport
// puller so Retry-After and body handling cannot drift between paths.
func NewHTTPStatusError(statusCode int, method, url string, h http.Header, body []byte, readErr error) *HTTPStatusError {
	retryAfter, hasRetryAfter := ParseRetryAfterPresent(h.Get("Retry-After"))
	var bodyStr string
	if readErr == nil {
		bodyStr = strings.TrimSpace(string(body))
	}
	return &HTTPStatusError{
		StatusCode:    statusCode,
		Method:        method,
		URL:           url,
		RetryAfter:    retryAfter,
		HasRetryAfter: hasRetryAfter,
		Body:          bodyStr,
	}
}

// NewHTTPStatusErrorFromResponse reads the truncated (4KB limit) response
// body and builds the canonical *HTTPStatusError for a non-2xx response.
// The caller remains responsible for closing resp.Body. It shares
// NewHTTPStatusError so the puller and DoJSONRequest observe identical
// Retry-After and body truncation behavior.
func NewHTTPStatusErrorFromResponse(resp *http.Response, method, url string) *HTTPStatusError {
	var body []byte
	var readErr error
	var header http.Header
	var statusCode int
	if resp != nil {
		statusCode = resp.StatusCode
		header = resp.Header
		if resp.Body != nil {
			body, readErr = io.ReadAll(io.LimitReader(resp.Body, 4096))
		}
	}
	return NewHTTPStatusError(statusCode, method, url, header, body, readErr)
}

// AddJitter returns d with up to 10% additional jitter capped at 1s to avoid
// lockstep retries. Non-positive delays are returned unchanged. It is the
// single canonical jitter helper shared by the transport SSE reconnect and
// the core SSE re-auth backoff so retry spread cannot drift between paths.
func AddJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	jitterCap := d / 10
	if jitterCap > time.Second {
		jitterCap = time.Second
	}
	if jitterCap > 0 {
		d += time.Duration(rand.Int63n(int64(jitterCap) + 1))
	}
	return d
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
		httpErr := NewHTTPStatusErrorFromResponse(resp, method, url)
		if cErr := resp.Body.Close(); cErr != nil {
			log.Warn("close body failed", "error", cErr)
		}
		if httpErr.Body != "" {
			return nil, fmt.Errorf("request failed: %w (body: %s)", httpErr, httpErr.Body)
		}
		return nil, fmt.Errorf("request failed: %w", httpErr)
	}

	return resp, nil
}
