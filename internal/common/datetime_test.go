package common

import (
	"testing"
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
