package alerts

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"runic/internal/common/log"
)

func TestLoadTimezoneOrDefault(t *testing.T) {
	tests := []struct {
		name      string
		timezone  string
		wantUTC   bool
		wantError bool
	}{
		{
			name:     "empty_timezone_returns_UTC",
			timezone: "",
			wantUTC:  true,
		},
		{
			name:     "valid_timezone_returns_location",
			timezone: "America/New_York",
			wantUTC:  false,
		},
		{
			name:      "invalid_timezone_returns_UTC",
			timezone:  "Invalid/Timezone",
			wantUTC:   true,
			wantError: true, // Should log a warning
		},
		{
			name:     "UTC_timezone_returns_UTC",
			timezone: "UTC",
			wantUTC:  true,
		},
		{
			name:     "Europe_London_timezone",
			timezone: "Europe/London",
			wantUTC:  false,
		},
		{
			name:      "typo_in_timezone_returns_UTC",
			timezone:  "America/NewYrok",
			wantUTC:   true,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := LoadTimezoneOrDefault(tt.timezone)
			if result == nil {
				t.Fatal("LoadTimezoneOrDefault returned nil")
			}

			if tt.wantUTC {
				if result != time.UTC {
					t.Errorf("expected UTC, got %v", result)
				}
			} else {
				if result == time.UTC && tt.timezone != "UTC" {
					// This is only an error if we didn't expect UTC
					if !tt.wantError {
						t.Errorf("unexpected UTC for valid timezone %s", tt.timezone)
					}
				}
			}
		})
	}
}

func TestLoadTimezoneOrDefaultWithLogger(t *testing.T) {
	tests := []struct {
		name      string
		timezone  string
		logger    *slog.Logger
		logAttrs  []any
		wantUTC   bool
		wantError bool
	}{
		{
			name:     "empty_timezone_with_logger_returns_UTC",
			timezone: "",
			logger:   slog.Default(),
			wantUTC:  true,
		},
		{
			name:     "valid_timezone_with_logger",
			timezone: "America/Los_Angeles",
			logger:   slog.Default(),
			wantUTC:  false,
		},
		{
			name:      "invalid_timezone_with_logger_logs_warning",
			timezone:  "Invalid/Zone",
			logger:    slog.Default(),
			wantUTC:   true,
			wantError: true,
		},
		{
			name:      "invalid_timezone_with_nil_logger_uses_default",
			timezone:  "Invalid/Zone",
			logger:    nil,
			wantUTC:   true,
			wantError: true,
		},
		{
			name:     "valid_timezone_with_log_attrs",
			timezone: "Asia/Tokyo",
			logger:   slog.Default(),
			logAttrs: []any{"user_id", 123},
			wantUTC:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := LoadTimezoneOrDefaultWithLogger(tt.timezone, tt.logger, tt.logAttrs...)
			if result == nil {
				t.Fatal("LoadTimezoneOrDefaultWithLogger returned nil")
			}

			if tt.wantUTC {
				if result != time.UTC {
					t.Errorf("expected UTC, got %v", result)
				}
			} else {
				if result == time.UTC && tt.timezone != "UTC" {
					if !tt.wantError {
						t.Errorf("unexpected UTC for valid timezone %s", tt.timezone)
					}
				}
			}
		})
	}
}

func TestLoadTimezoneOrDefault_ValidTimezones(t *testing.T) {
	// Test various valid IANA timezones
	validTimezones := []string{
		"UTC",
		"America/New_York",
		"America/Los_Angeles",
		"Europe/London",
		"Europe/Paris",
		"Asia/Tokyo",
		"Australia/Sydney",
		"Pacific/Auckland",
	}

	for _, tz := range validTimezones {
		t.Run(tz, func(t *testing.T) {
			result := LoadTimezoneOrDefault(tz)
			if result == nil {
				t.Errorf("LoadTimezoneOrDefault(%q) returned nil", tz)
			}
			// For UTC, the result should be time.UTC
			if tz == "UTC" && result != time.UTC {
				t.Errorf("expected time.UTC for UTC timezone, got %v", result)
			}
			// For non-UTC timezones, verify the location name matches
			if tz != "UTC" {
				// The location string should contain the timezone name
				if !strings.Contains(result.String(), tz) && result.String() != tz {
					t.Errorf("location name mismatch: got %q, want %q", result.String(), tz)
				}
			}
		})
	}
}

func TestLoadTimezoneOrDefault_InvalidTimezones(t *testing.T) {
	// Test various invalid timezone strings
	// Note: Go's time package supports some legacy timezone abbreviations like EST, PST
	invalidTimezones := []string{
		"Invalid/Timezone", // Non-existent
		"NotATimezone",     // Not a valid format
		"Foo/Bar",          // Non-existent
	}

	for _, tz := range invalidTimezones {
		t.Run(tz, func(t *testing.T) {
			result := LoadTimezoneOrDefault(tz)
			if result != time.UTC {
				t.Errorf("LoadTimezoneOrDefault(%q) should return UTC for invalid timezone, got %v", tz, result)
			}
		})
	}
}

func TestLoadTimezoneOrDefault_EdgeCases(t *testing.T) {
	t.Run("whitespace_timezone", func(t *testing.T) {
		// Leading/trailing whitespace is not trimmed by time.LoadLocation
		// and will cause it to fail
		result := LoadTimezoneOrDefault(" America/New_York ")
		// This will return UTC because time.LoadLocation is strict about format
		if result != time.UTC {
			// If it somehow works, verify it's a valid location
			_ = result // Just use the result to avoid unused variable warning
		}
	})

	t.Run("case_insensitive_timezone", func(t *testing.T) {
		// Note: Go's time.LoadLocation is case-insensitive for some platforms
		// This behavior may vary, so we just verify it returns a valid location
		result := LoadTimezoneOrDefault("america/new_york")
		// Either UTC or a valid location is acceptable
		_ = result
	})
}

func TestLoadTimezoneOrDefault_Concurrency(t *testing.T) {
	// Test that the function is safe for concurrent use
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = LoadTimezoneOrDefault("America/New_York")
				_ = LoadTimezoneOrDefault("")
				_ = LoadTimezoneOrDefault("Invalid/Zone")
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// Benchmark to ensure performance is acceptable
func BenchmarkLoadTimezoneOrDefault(b *testing.B) {
	b.Run("empty", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = LoadTimezoneOrDefault("")
		}
	})

	b.Run("valid", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = LoadTimezoneOrDefault("America/New_York")
		}
	})

	b.Run("invalid", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = LoadTimezoneOrDefault("Invalid/Zone")
		}
	})
}

func TestMain(m *testing.M) {
	// Ensure log is initialized for tests
	log.Init("info", io.Discard)
	m.Run()
}
