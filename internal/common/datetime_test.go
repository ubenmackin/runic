package common

import (
	"strings"
	"testing"
	"time"
)

func TestFormatSQLiteDatetime(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty string returns empty string",
			input: "",
			want:  "",
		},
		{
			name:  "valid SQLite datetime converts to RFC 3339",
			input: "2024-01-15 12:00:00",
			want:  "2024-01-15T12:00:00Z",
		},
		{
			name:  "valid SQLite datetime with different values",
			input: "2023-06-30 23:59:59",
			want:  "2023-06-30T23:59:59Z",
		},
		{
			name:  "invalid string returned unchanged",
			input: "not-a-datetime",
			want:  "not-a-datetime",
		},
		{
			name:  "partial datetime returned unchanged",
			input: "2024-01-15",
			want:  "2024-01-15",
		},
		{
			name:  "already RFC 3339 format returned unchanged via RFC 3339 detection",
			input: "2024-01-15T12:00:00Z",
			want:  "2024-01-15T12:00:00Z",
		},
		{
			name:  "SQLite datetime at midnight",
			input: "2024-01-01 00:00:00",
			want:  "2024-01-01T00:00:00Z",
		},
		{
			name:  "RFC 3339 with timezone offset returned unchanged",
			input: "2024-01-15T10:00:00+02:00",
			want:  "2024-01-15T10:00:00+02:00",
		},
		{
			name:  "string that looks like datetime but has extra chars returned unchanged",
			input: "2024-01-15 12:00:00 extra",
			want:  "2024-01-15 12:00:00 extra",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatSQLiteDatetime(tt.input)
			if got != tt.want {
				t.Errorf("FormatSQLiteDatetime(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeFirewallTimestamp(t *testing.T) {
	now := time.Date(2026, time.November, 25, 12, 0, 0, 0, time.UTC)
	rolloverNow := time.Date(2026, time.January, 1, 0, 0, 30, 0, time.UTC)

	tests := []struct {
		name    string
		raw     string
		now     time.Time
		want    string
		wantErr bool
	}{
		{
			name: "RFC3339 with offset converts to UTC",
			raw:  "2026-11-25T19:40:01.123456789-07:00",
			now:  now,
			want: "2026-11-26 02:40:01",
		},
		{
			name: "RFC3339 with Z stays UTC",
			raw:  "2026-11-25T19:40:01Z",
			now:  now,
			want: "2026-11-25 19:40:01",
		},
		{
			name: "SQLite datetime is unchanged",
			raw:  "2026-11-25 19:40:01",
			now:  now,
			want: "2026-11-25 19:40:01",
		},
		{
			name: "SQLite datetime drops fractional seconds",
			raw:  "2026-11-25 19:40:01.123456789",
			now:  now,
			want: "2026-11-25 19:40:01",
		},
		{
			name: "date only fills midnight",
			raw:  "2026-11-25",
			now:  now,
			want: "2026-11-25 00:00:00",
		},
		{
			name: "T separated zone-less datetime parses as UTC",
			raw:  "2026-11-25T19:40:01",
			now:  now,
			want: "2026-11-25 19:40:01",
		},
		{
			name: "surrounding whitespace is trimmed",
			raw:  "  2026-11-25T19:40:01Z  ",
			now:  now,
			want: "2026-11-25 19:40:01",
		},
		{
			name: "syslog timestamp infers current year",
			raw:  "Nov 25 19:40:01",
			now:  now,
			want: "2026-11-25 19:40:01",
		},
		{
			name: "space padded syslog day parses",
			raw:  "Nov  5 19:40:01",
			now:  now,
			want: "2026-11-05 19:40:01",
		},
		{
			name: "syslog timestamp rolls back a year when in the future",
			raw:  "Dec 31 23:59:59",
			now:  rolloverNow,
			want: "2025-12-31 23:59:59",
		},
		{
			name: "syslog timestamp within one day of now keeps inferred year",
			raw:  "Nov 26 12:00:00",
			now:  now,
			want: "2026-11-26 12:00:00",
		},
		{
			name: "syslog timestamp just past one day rolls back",
			raw:  "Nov 26 12:00:01",
			now:  now,
			want: "2025-11-26 12:00:01",
		},
		{
			name: "exactly 64 bytes trims to a valid timestamp",
			raw:  strings.Repeat(" ", 44) + "2026-11-25T19:40:01Z",
			now:  now,
			want: "2026-11-25 19:40:01",
		},
		{
			name:    "over 64 bytes whitespace-padded valid timestamp is rejected",
			raw:     strings.Repeat(" ", 45) + "2026-11-25T19:40:01Z",
			now:     now,
			wantErr: true,
		},
		{
			name:    "over 64 bytes is rejected",
			raw:     strings.Repeat("x", 65),
			now:     now,
			wantErr: true,
		},
		{
			name:    "unrecognized input is rejected",
			raw:     "not-a-time",
			now:     now,
			wantErr: true,
		},
		{
			name:    "empty input is rejected",
			raw:     "",
			now:     now,
			wantErr: true,
		},
		{
			name:    "whitespace only input is rejected",
			raw:     "   ",
			now:     now,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeFirewallTimestamp(tt.raw, tt.now)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NormalizeFirewallTimestamp(%q) error = nil, want error", tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeFirewallTimestamp(%q) unexpected error: %v", tt.raw, err)
			}
			if got != tt.want {
				t.Errorf("NormalizeFirewallTimestamp(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestFirewallTimestampCutoff(t *testing.T) {
	tests := []struct {
		name string
		in   time.Time
		want string
	}{
		{
			name: "offset converts to UTC",
			in:   time.Date(2026, time.November, 25, 19, 40, 1, 0, time.FixedZone("MST", -7*60*60)),
			want: "2026-11-26 02:40:01",
		},
		{
			name: "fractional seconds are dropped",
			in:   time.Date(2026, time.November, 25, 19, 40, 1, 999999999, time.UTC),
			want: "2026-11-25 19:40:01",
		},
		{
			name: "UTC time is unchanged",
			in:   time.Date(2026, time.November, 25, 19, 40, 1, 0, time.UTC),
			want: "2026-11-25 19:40:01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FirewallTimestampCutoff(tt.in)
			if got != tt.want {
				t.Errorf("FirewallTimestampCutoff(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
