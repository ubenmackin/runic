package common

import (
	"testing"
)

// sharedTypeTestCases contains test cases shared by IsValidSourceType and IsValidTargetType
// since both functions validate the same set of allowed values: "peer", "group", "special".
var sharedTypeTestCases = []struct {
	name  string
	value string
	want  bool
}{
	// Valid inputs
	{
		name:  "valid peer",
		value: "peer",
		want:  true,
	},
	{
		name:  "valid group",
		value: "group",
		want:  true,
	},
	{
		name:  "valid special",
		value: "special",
		want:  true,
	},
	// Invalid inputs - wrong values
	{
		name:  "invalid value",
		value: "invalid",
		want:  false,
	},
	{
		name:  "invalid user",
		value: "user",
		want:  false,
	},
	{
		name:  "invalid policy",
		value: "policy",
		want:  false,
	},
	// Case sensitivity tests
	{
		name:  "uppercase PEER",
		value: "PEER",
		want:  false,
	},
	{
		name:  "uppercase GROUP",
		value: "GROUP",
		want:  false,
	},
	{
		name:  "uppercase SPECIAL",
		value: "SPECIAL",
		want:  false,
	},
	{
		name:  "mixed case Peer",
		value: "Peer",
		want:  false,
	},
	{
		name:  "mixed case Group",
		value: "Group",
		want:  false,
	},
	// Edge cases
	{
		name:  "empty string",
		value: "",
		want:  false,
	},
	{
		name:  "whitespace only",
		value: "   ",
		want:  false,
	},
	{
		name:  "peer with leading whitespace",
		value: " peer",
		want:  false,
	},
	{
		name:  "peer with trailing whitespace",
		value: "peer ",
		want:  false,
	},
	{
		name:  "peer with surrounding whitespace",
		value: " peer ",
		want:  false,
	},
	// Plural/singular variations
	{
		name:  "plural peers",
		value: "peers",
		want:  false,
	},
	{
		name:  "plural groups",
		value: "groups",
		want:  false,
	},
	{
		name:  "plural specials",
		value: "specials",
		want:  false,
	},
}

// runTypeValidationTests executes the shared type test cases against a given validation function.
func runTypeValidationTests(t *testing.T, fn func(string) bool, funcName string) {
	t.Helper()
	for _, tt := range sharedTypeTestCases {
		t.Run(tt.name, func(t *testing.T) {
			got := fn(tt.value)
			if got != tt.want {
				t.Errorf("%s(%q) = %v, want %v", funcName, tt.value, got, tt.want)
			}
		})
	}
}

// TestIsValidSourceType tests the IsValidSourceType validation function
func TestIsValidSourceType(t *testing.T) {
	runTypeValidationTests(t, IsValidSourceType, "IsValidSourceType")
}

// TestIsValidTargetType tests the IsValidTargetType validation function
func TestIsValidTargetType(t *testing.T) {
	runTypeValidationTests(t, IsValidTargetType, "IsValidTargetType")
}

// TestIsValidDirection tests the IsValidDirection validation function
func TestIsValidDirection(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		// Valid inputs
		{
			name:  "valid both",
			value: "both",
			want:  true,
		},
		{
			name:  "valid forward",
			value: "forward",
			want:  true,
		},
		{
			name:  "valid backward",
			value: "backward",
			want:  true,
		},
		// Invalid inputs - wrong values
		{
			name:  "invalid value",
			value: "invalid",
			want:  false,
		},
		{
			name:  "invalid inbound",
			value: "inbound",
			want:  false,
		},
		{
			name:  "invalid outbound",
			value: "outbound",
			want:  false,
		},
		{
			name:  "invalid bi-directional",
			value: "bi-directional",
			want:  false,
		},
		{
			name:  "invalid bidirectional",
			value: "bidirectional",
			want:  false,
		},
		{
			name:  "invalid in",
			value: "in",
			want:  false,
		},
		{
			name:  "invalid out",
			value: "out",
			want:  false,
		},
		// Case sensitivity tests
		{
			name:  "uppercase BOTH",
			value: "BOTH",
			want:  false,
		},
		{
			name:  "uppercase FORWARD",
			value: "FORWARD",
			want:  false,
		},
		{
			name:  "uppercase BACKWARD",
			value: "BACKWARD",
			want:  false,
		},
		{
			name:  "mixed case Both",
			value: "Both",
			want:  false,
		},
		{
			name:  "mixed case Forward",
			value: "Forward",
			want:  false,
		},
		{
			name:  "mixed case Backward",
			value: "Backward",
			want:  false,
		},
		// Edge cases
		{
			name:  "empty string",
			value: "",
			want:  false,
		},
		{
			name:  "whitespace only",
			value: "   ",
			want:  false,
		},
		{
			name:  "both with leading whitespace",
			value: " both",
			want:  false,
		},
		{
			name:  "both with trailing whitespace",
			value: "both ",
			want:  false,
		},
		{
			name:  "both with surrounding whitespace",
			value: " both ",
			want:  false,
		},
		// Common typos/variations
		{
			name:  "forwards variant",
			value: "forwards",
			want:  false,
		},
		{
			name:  "backwards variant",
			value: "backwards",
			want:  false,
		},
		{
			name:  "fwd abbreviation",
			value: "fwd",
			want:  false,
		},
		{
			name:  "bwd abbreviation",
			value: "bwd",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidDirection(tt.value)
			if got != tt.want {
				t.Errorf("IsValidDirection(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}
