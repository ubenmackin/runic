package common

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsUnauthorized(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantRes bool
	}{
		{
			name:    "ErrUnauthorized returns true",
			err:     ErrUnauthorized,
			wantRes: true,
		},
		{
			name:    "wrapped ErrUnauthorized returns true",
			err:     fmt.Errorf("wrapped: %w", ErrUnauthorized),
			wantRes: true,
		},
		{
			name: "HTTPStatusError with 401 returns true",
			err: &HTTPStatusError{
				StatusCode: 401,
				Method:     "GET",
				URL:        "/api/v1/peers",
			},
			wantRes: true,
		},
		{
			name: "HTTPStatusError with 403 returns false",
			err: &HTTPStatusError{
				StatusCode: 403,
				Method:     "GET",
				URL:        "/api/v1/peers",
			},
			wantRes: false,
		},
		{
			name:    "other error returns false",
			err:     errors.New("some other error"),
			wantRes: false,
		},
		{
			name:    "nil error returns false",
			err:     nil,
			wantRes: false,
		},
		{
			name: "wrapped HTTPStatusError with 401 returns true",
			err: fmt.Errorf("request failed: %w", &HTTPStatusError{
				StatusCode: 401,
				Method:     "POST",
				URL:        "/api/v1/login",
			}),
			wantRes: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsUnauthorized(tt.err); got != tt.wantRes {
				t.Errorf("IsUnauthorized(%v) = %v, want %v", tt.err, got, tt.wantRes)
			}
		})
	}
}

func TestErrUnauthorized(t *testing.T) {
	t.Run("ErrUnauthorized has correct message", func(t *testing.T) {
		want := "unauthorized: received 401 response"
		if got := ErrUnauthorized.Error(); got != want {
			t.Errorf("ErrUnauthorized.Error() = %q, want %q", got, want)
		}
	})

	t.Run("ErrUnauthorized matches itself with errors.Is", func(t *testing.T) {
		if !errors.Is(ErrUnauthorized, ErrUnauthorized) {
			t.Errorf("errors.Is(ErrUnauthorized, ErrUnauthorized) = false, want true")
		}
	})

	t.Run("wrapped ErrUnauthorized matches with errors.Is", func(t *testing.T) {
		wrapped := fmt.Errorf("wrapped: %w", ErrUnauthorized)
		if !errors.Is(wrapped, ErrUnauthorized) {
			t.Errorf("errors.Is(wrapped ErrUnauthorized, ErrUnauthorized) = false, want true")
		}
	})
}

func TestHTTPStatusError_ErrorsIs(t *testing.T) {
	t.Run("errors.Is recognizes 401 as ErrUnauthorized", func(t *testing.T) {
		err := &HTTPStatusError{
			StatusCode: 401,
			Method:     "GET",
			URL:        "/api/v1/peers",
		}

		if !errors.Is(err, ErrUnauthorized) {
			t.Errorf("errors.Is(401 HTTPStatusError, ErrUnauthorized) = false, want true")
		}
	})

	t.Run("errors.Is does not match 403 as ErrUnauthorized", func(t *testing.T) {
		err := &HTTPStatusError{
			StatusCode: 403,
			Method:     "GET",
			URL:        "/api/v1/peers",
		}

		if errors.Is(err, ErrUnauthorized) {
			t.Errorf("errors.Is(403 HTTPStatusError, ErrUnauthorized) = true, want false")
		}
	})

	t.Run("errors.Is does not match 500 as ErrUnauthorized", func(t *testing.T) {
		err := &HTTPStatusError{
			StatusCode: 500,
			Method:     "GET",
			URL:        "/api/v1/peers",
		}

		if errors.Is(err, ErrUnauthorized) {
			t.Errorf("errors.Is(500 HTTPStatusError, ErrUnauthorized) = true, want false")
		}
	})

	t.Run("errors.Is does not match 401 as other errors", func(t *testing.T) {
		err := &HTTPStatusError{
			StatusCode: 401,
			Method:     "GET",
			URL:        "/api/v1/peers",
		}

		otherErr := errors.New("some other error")
		if errors.Is(err, otherErr) {
			t.Errorf("errors.Is(401 HTTPStatusError, otherErr) = true, want false")
		}
	})
}

func TestHTTPStatusError_IsMethod(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		target     error
		want       bool
	}{
		{
			name:       "401 matches ErrUnauthorized",
			statusCode: 401,
			target:     ErrUnauthorized,
			want:       true,
		},
		{
			name:       "403 does not match ErrUnauthorized",
			statusCode: 403,
			target:     ErrUnauthorized,
			want:       false,
		},
		{
			name:       "500 does not match ErrUnauthorized",
			statusCode: 500,
			target:     ErrUnauthorized,
			want:       false,
		},
		{
			name:       "nil target returns false",
			statusCode: 401,
			target:     nil,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &HTTPStatusError{StatusCode: tt.statusCode}
			if got := err.Is(tt.target); got != tt.want {
				t.Errorf("HTTPStatusError.Is(%v) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestHTTPStatusError_Printf(t *testing.T) {
	err := &HTTPStatusError{
		StatusCode: 404,
		Method:     "GET",
		URL:        "/api/v1/peers/123",
	}

	// Test that Error() is called when formatting
	got := fmt.Sprintf("%s", err)
	want := "HTTP 404 GET /api/v1/peers/123"
	if got != want {
		t.Errorf("fmt.Sprintf error = %q, want %q", got, want)
	}

	// Test %v format
	gotV := fmt.Sprintf("%v", err)
	if gotV != want {
		t.Errorf("fmt.Sprintf %%v error = %q, want %q", gotV, want)
	}
}

func TestHTTPStatusError_EdgeCases(t *testing.T) {
	t.Run("empty method and url", func(t *testing.T) {
		err := &HTTPStatusError{
			StatusCode: 500,
			Method:     "",
			URL:        "",
		}

		want := "HTTP 500  "
		if got := err.Error(); got != want {
			t.Errorf("HTTPStatusError.Error() with empty fields = %q, want %q", got, want)
		}
	})

	t.Run("unusual but valid status codes", func(t *testing.T) {
		err := &HTTPStatusError{
			StatusCode: 418, // I'm a teapot
			Method:     "BREW",
			URL:        "/coffee",
		}

		want := "HTTP 418 BREW /coffee"
		if got := err.Error(); got != want {
			t.Errorf("HTTPStatusError.Error() = %q, want %q", got, want)
		}
	})

	t.Run("very long URL", func(t *testing.T) {
		longURL := "/api/v1/very/long/path/that/goes/on/and/on/and/on/and/on/and/on"
		err := &HTTPStatusError{
			StatusCode: 404,
			Method:     "GET",
			URL:        longURL,
		}

		want := "HTTP 404 GET " + longURL
		if got := err.Error(); got != want {
			t.Errorf("HTTPStatusError.Error() with long URL = %q, want %q", got, want)
		}
	})
}

func TestHTTPStatusError_Composition(t *testing.T) {
	t.Run("wrap HTTPStatusError in custom error", func(t *testing.T) {
		httpErr := &HTTPStatusError{
			StatusCode: 401,
			Method:     "GET",
			URL:        "/api/v1/secrets",
		}

		wrappedErr := fmt.Errorf("failed to fetch secrets: %w", httpErr)

		// The wrapped error should still be recognized as ErrUnauthorized
		if !IsUnauthorized(wrappedErr) {
			t.Errorf("IsUnauthorized(wrapped HTTPStatusError) = false, want true")
		}

		// errors.Is should also work through the wrapping
		if !errors.Is(wrappedErr, ErrUnauthorized) {
			t.Errorf("errors.Is(wrapped HTTPStatusError, ErrUnauthorized) = false, want true")
		}
	})
}

func TestIsRateLimited(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "429 returns true",
			err: &HTTPStatusError{
				StatusCode: 429,
				Method:     "GET",
				URL:        "/api/v1/peers",
			},
			want: true,
		},
		{
			name: "wrapped 429 returns true",
			err: fmt.Errorf("request failed: %w", &HTTPStatusError{
				StatusCode: 429,
				Method:     "GET",
				URL:        "/api/v1/peers",
			}),
			want: true,
		},
		{
			name: "401 returns false",
			err: &HTTPStatusError{
				StatusCode: 401,
				Method:     "GET",
				URL:        "/api/v1/peers",
			},
			want: false,
		},
		{
			name: "403 returns false",
			err: &HTTPStatusError{
				StatusCode: 403,
				Method:     "GET",
				URL:        "/api/v1/peers",
			},
			want: false,
		},
		{
			name: "500 returns false",
			err: &HTTPStatusError{
				StatusCode: 500,
				Method:     "GET",
				URL:        "/api/v1/peers",
			},
			want: false,
		},
		{
			name: "other error returns false",
			err:  errors.New("some other error"),
			want: false,
		},
		{
			name: "nil returns false",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRateLimited(tt.err); got != tt.want {
				t.Errorf("IsRateLimited(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestRetryAfterOf(t *testing.T) {
	t.Run("missing header yields (0,false)", func(t *testing.T) {
		err := &HTTPStatusError{StatusCode: 429, Method: "GET", URL: "/x"}
		if d, ok := RetryAfterOf(err); d != 0 || ok {
			t.Errorf("RetryAfterOf() = (%v,%v), want (0,false)", d, ok)
		}
	})

	t.Run("delta-seconds yields duration and true", func(t *testing.T) {
		err := &HTTPStatusError{StatusCode: 429, RetryAfter: 2 * time.Second, HasRetryAfter: true}
		if d, ok := RetryAfterOf(err); d != 2*time.Second || !ok {
			t.Errorf("RetryAfterOf() = (%v,%v), want (2s,true)", d, ok)
		}
	})

	t.Run("present zero yields (0,true)", func(t *testing.T) {
		err := &HTTPStatusError{StatusCode: 429, RetryAfter: 0, HasRetryAfter: true}
		if d, ok := RetryAfterOf(err); d != 0 || !ok {
			t.Errorf("RetryAfterOf() = (%v,%v), want (0,true)", d, ok)
		}
	})

	t.Run("negative yields (0,true)", func(t *testing.T) {
		err := &HTTPStatusError{StatusCode: 429, RetryAfter: -time.Second, HasRetryAfter: true}
		if d, ok := RetryAfterOf(err); d != 0 || !ok {
			t.Errorf("RetryAfterOf() = (%v,%v), want (0,true)", d, ok)
		}
	})

	t.Run("non-HTTP error yields (0,false)", func(t *testing.T) {
		if d, ok := RetryAfterOf(errors.New("boom")); d != 0 || ok {
			t.Errorf("RetryAfterOf() = (%v,%v), want (0,false)", d, ok)
		}
	})

	t.Run("nil yields (0,false)", func(t *testing.T) {
		if d, ok := RetryAfterOf(nil); d != 0 || ok {
			t.Errorf("RetryAfterOf() = (%v,%v), want (0,false)", d, ok)
		}
	})

	t.Run("wrapped 429 preserves retry-after", func(t *testing.T) {
		inner := &HTTPStatusError{StatusCode: 429, RetryAfter: 5 * time.Second, HasRetryAfter: true}
		err := fmt.Errorf("request failed: %w", inner)
		if d, ok := RetryAfterOf(err); d != 5*time.Second || !ok {
			t.Errorf("RetryAfterOf() = (%v,%v), want (5s,true)", d, ok)
		}
		if !IsRateLimited(err) {
			t.Errorf("IsRateLimited(wrapped 429) = false, want true")
		}
	})
}

func TestHTTPStatusError_ErrorStableWithNewFields(t *testing.T) {
	err := &HTTPStatusError{
		StatusCode:    429,
		Method:        "GET",
		URL:           "/api/v1/peers",
		RetryAfter:    2 * time.Second,
		HasRetryAfter: true,
		Body:          "rate limited",
	}
	want := "HTTP 429 GET /api/v1/peers"
	if got := err.Error(); got != want {
		t.Errorf("HTTPStatusError.Error() with RetryAfter/Body = %q, want %q", got, want)
	}
}

func TestHTTPStatusError_RetryAfterDoesNotAffectIs(t *testing.T) {
	t.Run("429 with RetryAfter does not match ErrUnauthorized", func(t *testing.T) {
		err := &HTTPStatusError{StatusCode: 429, RetryAfter: 2 * time.Second, HasRetryAfter: true}
		if errors.Is(err, ErrUnauthorized) {
			t.Errorf("errors.Is(429 with RetryAfter, ErrUnauthorized) = true, want false")
		}
	})

	t.Run("401 with RetryAfter still matches ErrUnauthorized", func(t *testing.T) {
		err := &HTTPStatusError{StatusCode: 401, RetryAfter: 2 * time.Second, HasRetryAfter: true}
		if !errors.Is(err, ErrUnauthorized) {
			t.Errorf("errors.Is(401 with RetryAfter, ErrUnauthorized) = false, want true")
		}
	})

	t.Run("403 with RetryAfter does not match ErrUnauthorized", func(t *testing.T) {
		err := &HTTPStatusError{StatusCode: 403, RetryAfter: 2 * time.Second, HasRetryAfter: true}
		if errors.Is(err, ErrUnauthorized) {
			t.Errorf("errors.Is(403 with RetryAfter, ErrUnauthorized) = true, want false")
		}
	})
}

func TestDoJSONRequest429MapsToRateLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("rate limited"))
	}))
	defer server.Close()

	_, err := DoJSONRequest(context.Background(), server.Client(), "GET", server.URL, nil, "", "")
	if err == nil {
		t.Fatal("DoJSONRequest() expected error for 429, got nil")
	}
	if !IsRateLimited(err) {
		t.Errorf("IsRateLimited(429 err) = false, want true")
	}
	if IsUnauthorized(err) {
		t.Errorf("IsUnauthorized(429 err) = true, want false")
	}
	if errors.Is(err, ErrUnauthorized) {
		t.Errorf("errors.Is(429 err, ErrUnauthorized) = true, want false")
	}
	d, ok := RetryAfterOf(err)
	if !ok {
		t.Fatal("RetryAfterOf(429 with Retry-After:2) ok = false, want true")
	}
	if d < 1500*time.Millisecond || d > 2500*time.Millisecond {
		t.Errorf("RetryAfterOf(429) = %v, want ~2s", d)
	}
	var httpErr *HTTPStatusError
	if !errors.As(err, &httpErr) {
		t.Fatalf("error does not wrap *HTTPStatusError: %v", err)
	}
	if httpErr.StatusCode != http.StatusTooManyRequests {
		t.Errorf("StatusCode = %d, want 429", httpErr.StatusCode)
	}
	want := fmt.Sprintf("HTTP 429 GET %s", server.URL)
	if got := httpErr.Error(); got != want {
		t.Errorf("HTTPStatusError.Error() = %q, want %q (format must stay stable)", got, want)
	}
}

func TestDoJSONRequest401MapsToUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
	}))
	defer server.Close()

	_, err := DoJSONRequest(context.Background(), server.Client(), "GET", server.URL, nil, "", "")
	if err == nil {
		t.Fatal("DoJSONRequest() expected error for 401, got nil")
	}
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("errors.Is(401 err, ErrUnauthorized) = false, want true")
	}
	if !IsUnauthorized(err) {
		t.Errorf("IsUnauthorized(401 err) = false, want true")
	}
	if IsRateLimited(err) {
		t.Errorf("IsRateLimited(401 err) = true, want false")
	}
	var httpErr *HTTPStatusError
	if !errors.As(err, &httpErr) {
		t.Fatalf("error does not wrap *HTTPStatusError: %v", err)
	}
	want := fmt.Sprintf("HTTP 401 GET %s", server.URL)
	if got := httpErr.Error(); got != want {
		t.Errorf("HTTPStatusError.Error() = %q, want %q (format must stay stable)", got, want)
	}
}
