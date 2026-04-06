package common

import (
	"errors"
	"fmt"
	"testing"
)

// TestIsUnauthorized tests the IsUnauthorized helper function
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

// TestErrUnauthorized tests the ErrUnauthorized sentinel error
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

// TestHTTPStatusError_ErrorsIs tests that errors.Is() works with HTTPStatusError
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

// TestHTTPStatusError_IsMethod tests HTTPStatusError.Is() directly
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

// TestHTTPStatusError_Printf tests formatting HTTPStatusError with fmt
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

// TestHTTPStatusError_EdgeCases tests edge cases for HTTPStatusError
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

// TestHTTPStatusError_Composition tests error composition patterns
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
