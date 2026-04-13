// Package alerts provides alert and notification functionality.
package alerts

import (
	"strings"
	"testing"
)

// TestSanitizeAlertInput_XSSPayloads tests that XSS payloads with control characters
// are properly sanitized. Note: SanitizeAlertInput removes control characters but
// preserves angle brackets. Use SanitizeAlertInputStrict for HTML escaping.
func TestSanitizeAlertInput_XSSPayloads(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		maxLen      int
		wantResult  string
		wantChanged bool
	}{
		{
			name:        "script tag preserved (control char removal only)",
			input:       "<script>alert('xss')</script>",
			maxLen:      255,
			wantResult:  "<script>alert('xss')</script>",
			wantChanged: false,
		},
		{
			name:        "script with control characters - control chars removed",
			input:       "<script>\nalert('xss')\r</script>",
			maxLen:      255,
			wantResult:  "<script>alert('xss')</script>",
			wantChanged: true,
		},
		{
			name:        "img tag preserved (control char removal only)",
			input:       "<img src=x onerror=alert('xss')>",
			maxLen:      255,
			wantResult:  "<img src=x onerror=alert('xss')>",
			wantChanged: false,
		},
		{
			name:        "javascript protocol preserved",
			input:       "javascript:alert('xss')",
			maxLen:      255,
			wantResult:  "javascript:alert('xss')",
			wantChanged: false,
		},
		{
			name:        "svg with control chars - control chars removed",
			input:       "<svg\nonload=alert('xss')>",
			maxLen:      255,
			wantResult:  "<svgonload=alert('xss')>",
			wantChanged: true,
		},
		{
			name:        "event handler with newline",
			input:       "\" onmouseover\n=\"alert('xss')\"",
			maxLen:      255,
			wantResult:  "\" onmouseover=\"alert('xss')\"",
			wantChanged: true,
		},
		{
			name:        "XSS with NUL character",
			input:       "<scr\x00ipt>alert('xss')</script>",
			maxLen:      255,
			wantResult:  "<script>alert('xss')</script>",
			wantChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotChanged := SanitizeAlertInput(tt.input, tt.maxLen)
			if gotResult != tt.wantResult {
				t.Errorf("SanitizeAlertInput(%q, %d) = %q, want %q", tt.input, tt.maxLen, gotResult, tt.wantResult)
			}
			if gotChanged != tt.wantChanged {
				t.Errorf("SanitizeAlertInput(%q, %d) changed = %v, want %v", tt.input, tt.maxLen, gotChanged, tt.wantChanged)
			}
		})
	}
}

// TestSanitizeAlertInput_HeaderInjection tests that header injection is prevented.
func TestSanitizeAlertInput_HeaderInjection(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		maxLen      int
		wantResult  string
		wantChanged bool
	}{
		{
			name:        "Bcc header injection",
			input:       "test\r\nBcc: victim@example.com",
			maxLen:      255,
			wantResult:  "testBcc: victim@example.com",
			wantChanged: true,
		},
		{
			name:        "multiple header injection",
			input:       "test\r\nTo: victim1@example.com\r\nCc: victim2@example.com",
			maxLen:      255,
			wantResult:  "testTo: victim1@example.comCc: victim2@example.com",
			wantChanged: true,
		},
		{
			name:        "LF only header injection",
			input:       "test\nBcc: victim@example.com",
			maxLen:      255,
			wantResult:  "testBcc: victim@example.com",
			wantChanged: true,
		},
		{
			name:        "CR only header injection",
			input:       "test\rBcc: victim@example.com",
			maxLen:      255,
			wantResult:  "testBcc: victim@example.com",
			wantChanged: true,
		},
		{
			name:        "mixed line endings",
			input:       "test\r\n\n\rBcc: victim@example.com",
			maxLen:      255,
			wantResult:  "testBcc: victim@example.com",
			wantChanged: true,
		},
		{
			name:        "double CRLF for body injection",
			input:       "test\r\n\r\nInjected body content",
			maxLen:      255,
			wantResult:  "testInjected body content",
			wantChanged: true,
		},
		{
			name:        "header injection with spaces",
			input:       " test \r\n Bcc: victim@example.com ",
			maxLen:      255,
			wantResult:  "test  Bcc: victim@example.com",
			wantChanged: true,
		},
		{
			name:        "subject header injection",
			input:       "normal subject\r\nSubject: fake subject",
			maxLen:      255,
			wantResult:  "normal subjectSubject: fake subject",
			wantChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotChanged := SanitizeAlertInput(tt.input, tt.maxLen)
			if gotResult != tt.wantResult {
				t.Errorf("SanitizeAlertInput(%q, %d) = %q, want %q", tt.input, tt.maxLen, gotResult, tt.wantResult)
			}
			if gotChanged != tt.wantChanged {
				t.Errorf("SanitizeAlertInput(%q, %d) changed = %v, want %v", tt.input, tt.maxLen, gotChanged, tt.wantChanged)
			}
		})
	}
}

// TestSanitizeAlertInput_ControlCharacters tests removal of various control characters.
func TestSanitizeAlertInput_ControlCharacters(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		maxLen      int
		wantResult  string
		wantChanged bool
	}{
		{
			name:        "NUL character removed",
			input:       "test\x00input",
			maxLen:      255,
			wantResult:  "testinput",
			wantChanged: true,
		},
		{
			name:        "bell character removed",
			input:       "test\x07input",
			maxLen:      255,
			wantResult:  "testinput",
			wantChanged: true,
		},
		{
			name:        "backspace character removed",
			input:       "test\x08input",
			maxLen:      255,
			wantResult:  "testinput",
			wantChanged: true,
		},
		{
			name:        "tab character removed",
			input:       "test\tinput",
			maxLen:      255,
			wantResult:  "testinput",
			wantChanged: true,
		},
		{
			name:        "form feed removed",
			input:       "test\x0cinput",
			maxLen:      255,
			wantResult:  "testinput",
			wantChanged: true,
		},
		{
			name:        "DEL character removed",
			input:       "test\x7Finput",
			maxLen:      255,
			wantResult:  "testinput",
			wantChanged: true,
		},
		{
			name:        "multiple control characters",
			input:       "\x00\x01\x02test\x03\x04",
			maxLen:      255,
			wantResult:  "test",
			wantChanged: true,
		},
		{
			name:        "control characters at start and end",
			input:       "\x00\x1Ftest\x7F",
			maxLen:      255,
			wantResult:  "test",
			wantChanged: true,
		},
		{
			name:        "escape character removed",
			input:       "test\x1binput",
			maxLen:      255,
			wantResult:  "testinput",
			wantChanged: true,
		},
		{
			name:        "all ASCII control chars removed",
			input:       "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0ftest",
			maxLen:      255,
			wantResult:  "test",
			wantChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotChanged := SanitizeAlertInput(tt.input, tt.maxLen)
			if gotResult != tt.wantResult {
				t.Errorf("SanitizeAlertInput() = %q, want %q", gotResult, tt.wantResult)
			}
			if gotChanged != tt.wantChanged {
				t.Errorf("SanitizeAlertInput() changed = %v, want %v", gotChanged, tt.wantChanged)
			}
		})
	}
}

// TestSanitizeAlertInput_LengthTruncation tests that long strings are properly truncated.
func TestSanitizeAlertInput_LengthTruncation(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		maxLen      int
		wantResult  string
		wantChanged bool
	}{
		{
			name:        "exact length string unchanged",
			input:       "exact",
			maxLen:      5,
			wantResult:  "exact",
			wantChanged: false,
		},
		{
			name:        "shorter string unchanged",
			input:       "short",
			maxLen:      10,
			wantResult:  "short",
			wantChanged: false,
		},
		{
			name:        "longer string truncated",
			input:       "this is a very long string that needs truncation",
			maxLen:      10,
			wantResult:  "this is a ",
			wantChanged: true,
		},
		{
			name:        "maxLen of zero does not truncate",
			input:       "test input",
			maxLen:      0,
			wantResult:  "test input",
			wantChanged: false,
		},
		{
			name:        "negative maxLen ignored",
			input:       "test input",
			maxLen:      -1,
			wantResult:  "test input",
			wantChanged: false,
		},
		{
			name:        "truncation with spaces trimmed",
			input:       "   this is long   ",
			maxLen:      5,
			wantResult:  "this ",
			wantChanged: true,
		},
		{
			name:        "very long hostname truncated to 255",
			input:       strings.Repeat("a", 300),
			maxLen:      255,
			wantResult:  strings.Repeat("a", 255),
			wantChanged: true,
		},
		{
			name:        "truncation preserves ASCII",
			input:       "hello world 123 !@#",
			maxLen:      10,
			wantResult:  "hello worl",
			wantChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotChanged := SanitizeAlertInput(tt.input, tt.maxLen)
			if gotResult != tt.wantResult {
				t.Errorf("SanitizeAlertInput() = %q, want %q", gotResult, tt.wantResult)
			}
			if gotChanged != tt.wantChanged {
				t.Errorf("SanitizeAlertInput() changed = %v, want %v", gotChanged, tt.wantChanged)
			}
		})
	}
}

// TestSanitizeAlertInput_UTF8Truncation tests that UTF-8 strings are handled correctly.
// Note: The current truncateString implementation has limitations with UTF-8 boundaries.
func TestSanitizeAlertInput_UTF8Truncation(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		maxLen      int
		wantResult  string
		wantChanged bool
	}{
		{
			name:        "UTF-8 string unchanged when under limit",
			input:       "日本語テスト",
			maxLen:      100,
			wantResult:  "日本語テスト",
			wantChanged: false,
		},
		{
			name:        "UTF-8 exact boundary - full string",
			input:       "日本語テスト",
			maxLen:      18, // Full string length (6 chars * 3 bytes)
			wantResult:  "日本語テスト",
			wantChanged: false,
		},
		{
			name:        "UTF-8 string with ASCII prefix",
			input:       "hello世界world",
			maxLen:      100,
			wantResult:  "hello世界world",
			wantChanged: false,
		},
		{
			name:        "ASCII truncation works correctly",
			input:       "hello world test",
			maxLen:      5,
			wantResult:  "hello",
			wantChanged: true,
		},
		{
			name:        "Mixed content truncation at ASCII boundary",
			input:       "hello世界world",
			maxLen:      5, // Just ASCII part
			wantResult:  "hello",
			wantChanged: true,
		},
		{
			name:        "UTF-8 content no truncation",
			input:       "日本語",
			maxLen:      10, // More than needed
			wantResult:  "日本語",
			wantChanged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotChanged := SanitizeAlertInput(tt.input, tt.maxLen)
			if gotResult != tt.wantResult {
				t.Errorf("SanitizeAlertInput() = %q, want %q", gotResult, tt.wantResult)
			}
			if gotChanged != tt.wantChanged {
				t.Errorf("SanitizeAlertInput() changed = %v, want %v", gotChanged, tt.wantChanged)
			}
		})
	}
}

// TestSanitizeAlertInput_ValidHostnames tests that valid hostnames pass through unchanged.
func TestSanitizeAlertInput_ValidHostnames(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		maxLen      int
		wantResult  string
		wantChanged bool
	}{
		{
			name:        "simple hostname unchanged",
			input:       "example.com",
			maxLen:      255,
			wantResult:  "example.com",
			wantChanged: false,
		},
		{
			name:        "hostname with subdomain",
			input:       "server.example.com",
			maxLen:      255,
			wantResult:  "server.example.com",
			wantChanged: false,
		},
		{
			name:        "hostname with numbers",
			input:       "server123.example.com",
			maxLen:      255,
			wantResult:  "server123.example.com",
			wantChanged: false,
		},
		{
			name:        "hostname with hyphen",
			input:       "my-server.example.com",
			maxLen:      255,
			wantResult:  "my-server.example.com",
			wantChanged: false,
		},
		{
			name:        "valid IP address unchanged",
			input:       "192.168.1.100",
			maxLen:      45,
			wantResult:  "192.168.1.100",
			wantChanged: false,
		},
		{
			name:        "IPv6 address unchanged",
			input:       "2001:db8::1",
			maxLen:      45,
			wantResult:  "2001:db8::1",
			wantChanged: false,
		},
		{
			name:        "short hostname",
			input:       "localhost",
			maxLen:      255,
			wantResult:  "localhost",
			wantChanged: false,
		},
		{
			name:        "FQDN",
			input:       "server.example.org.",
			maxLen:      255,
			wantResult:  "server.example.org.",
			wantChanged: false,
		},
		{
			name:        "hostname with leading space trimmed",
			input:       " example.com",
			maxLen:      255,
			wantResult:  "example.com",
			wantChanged: true,
		},
		{
			name:        "hostname with trailing space trimmed",
			input:       "example.com ",
			maxLen:      255,
			wantResult:  "example.com",
			wantChanged: true,
		},
		{
			name:        "valid hostname with underscore",
			input:       "my_server.example.com",
			maxLen:      255,
			wantResult:  "my_server.example.com",
			wantChanged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotChanged := SanitizeAlertInput(tt.input, tt.maxLen)
			if gotResult != tt.wantResult {
				t.Errorf("SanitizeAlertInput(%q, %d) = %q, want %q", tt.input, tt.maxLen, gotResult, tt.wantResult)
			}
			if gotChanged != tt.wantChanged {
				t.Errorf("SanitizeAlertInput(%q, %d) changed = %v, want %v", tt.input, tt.maxLen, gotChanged, tt.wantChanged)
			}
		})
	}
}

// TestSanitizeAlertInput_EmptyInput tests empty and whitespace-only inputs.
func TestSanitizeAlertInput_EmptyInput(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		maxLen      int
		wantResult  string
		wantChanged bool
	}{
		{
			name:        "empty string",
			input:       "",
			maxLen:      255,
			wantResult:  "",
			wantChanged: false,
		},
		{
			name:        "only whitespace trimmed to empty",
			input:       "   ",
			maxLen:      255,
			wantResult:  "",
			wantChanged: true,
		},
		{
			name:        "only tabs trimmed to empty",
			input:       "\t\t\t",
			maxLen:      255,
			wantResult:  "",
			wantChanged: true,
		},
		{
			name:        "only newlines trimmed to empty",
			input:       "\n\n\n",
			maxLen:      255,
			wantResult:  "",
			wantChanged: true,
		},
		{
			name:        "mixed whitespace trimmed to empty",
			input:       " \t\n\r ",
			maxLen:      255,
			wantResult:  "",
			wantChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotChanged := SanitizeAlertInput(tt.input, tt.maxLen)
			if gotResult != tt.wantResult {
				t.Errorf("SanitizeAlertInput() = %q, want %q", gotResult, tt.wantResult)
			}
			if gotChanged != tt.wantChanged {
				t.Errorf("SanitizeAlertInput() changed = %v, want %v", gotChanged, tt.wantChanged)
			}
		})
	}
}

// TestSanitizeAlertInput_SpecialCharacters tests handling of special characters.
func TestSanitizeAlertInput_SpecialCharacters(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		maxLen      int
		wantResult  string
		wantChanged bool
	}{
		{
			name:        "special characters preserved",
			input:       "test!@#$%^&*()",
			maxLen:      255,
			wantResult:  "test!@#$%^&*()",
			wantChanged: false,
		},
		{
			name:        "brackets preserved",
			input:       "test[]{}|\\",
			maxLen:      255,
			wantResult:  "test[]{}|\\",
			wantChanged: false,
		},
		{
			name:        "quotes preserved",
			input:       `test"single'quotes`,
			maxLen:      255,
			wantResult:  `test"single'quotes`,
			wantChanged: false,
		},
		{
			name:        "unicode preserved",
			input:       "test-αβγδ-日本語",
			maxLen:      255,
			wantResult:  "test-αβγδ-日本語",
			wantChanged: false,
		},
		{
			name:        "colon and semicolon preserved",
			input:       "test:value;another",
			maxLen:      255,
			wantResult:  "test:value;another",
			wantChanged: false,
		},
		{
			name:        "angle brackets preserved (non-strict mode)",
			input:       "<test>",
			maxLen:      255,
			wantResult:  "<test>",
			wantChanged: false,
		},
		{
			name:        "ampersand preserved (non-strict mode)",
			input:       "test & value",
			maxLen:      255,
			wantResult:  "test & value",
			wantChanged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotChanged := SanitizeAlertInput(tt.input, tt.maxLen)
			if gotResult != tt.wantResult {
				t.Errorf("SanitizeAlertInput() = %q, want %q", gotResult, tt.wantResult)
			}
			if gotChanged != tt.wantChanged {
				t.Errorf("SanitizeAlertInput() changed = %v, want %v", gotChanged, tt.wantChanged)
			}
		})
	}
}

// TestSanitizeAlertInput_NoCRORLF tests that no CR or LF characters remain in output.
func TestSanitizeAlertInput_NoCRORLF(t *testing.T) {
	payloads := []string{
		"test\r\nBcc: attacker@evil.com",
		"hello\nworld",
		"hello\rworld",
		"test\r\n\r\ninjected",
		"\r\n\r\n\r\n",
		"prefix\r\nX-Injected: value",
	}

	for i, payload := range payloads {
		t.Run("payload_"+string(rune('A'+i)), func(t *testing.T) {
			result, _ := SanitizeAlertInput(payload, 255)

			if strings.Contains(result, "\r") {
				t.Errorf("CR character not removed: %q", result)
			}
			if strings.Contains(result, "\n") {
				t.Errorf("LF character not removed: %q", result)
			}
		})
	}
}

// TestSanitizeAlertInput_NoControlChars tests that no control characters remain.
func TestSanitizeAlertInput_NoControlChars(t *testing.T) {
	// Test all ASCII control characters (0x00-0x1F and 0x7F)
	for c := byte(0x00); c <= 0x1F; c++ {
		input := string([]byte{'a', c, 'b'})
		result, modified := SanitizeAlertInput(input, 255)

		if !modified {
			t.Errorf("control character 0x%02X not detected as modification", c)
		}

		if strings.Contains(result, string(rune(c))) {
			t.Errorf("control character 0x%02X not removed from input", c)
		}
	}

	// Test DEL character (0x7F)
	input := string([]byte{'a', 0x7F, 'b'})
	result, modified := SanitizeAlertInput(input, 255)

	if !modified {
		t.Error("DEL character not detected as modification")
	}

	if strings.Contains(result, string(rune(0x7F))) {
		t.Error("DEL character not removed from input")
	}
}

// TestSanitizeAlertInput_CombinedAttacks tests combined attack patterns.
func TestSanitizeAlertInput_CombinedAttacks(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		maxLen      int
		wantResult  string
		wantChanged bool
	}{
		{
			name:        "XSS plus header injection - control chars removed",
			input:       "<script>alert('xss')</script>\r\nBcc: victim@example.com",
			maxLen:      255,
			wantResult:  "<script>alert('xss')</script>Bcc: victim@example.com",
			wantChanged: true,
		},
		{
			name:        "control chars plus XSS - control chars removed",
			input:       "\x00<script>\x1balert('xss')\r\n</script>",
			maxLen:      255,
			wantResult:  "<script>alert('xss')</script>",
			wantChanged: true,
		},
		{
			name:        "long XSS payload truncated",
			input:       "<script>" + strings.Repeat("a", 300) + "</script>",
			maxLen:      100,
			wantResult:  "<script>" + strings.Repeat("a", 92),
			wantChanged: true,
		},
		{
			name:        "header injection in long string",
			input:       strings.Repeat("a", 100) + "\r\nBcc: attacker@evil.com",
			maxLen:      50,
			wantResult:  strings.Repeat("a", 50),
			wantChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotChanged := SanitizeAlertInput(tt.input, tt.maxLen)
			if gotResult != tt.wantResult {
				t.Errorf("SanitizeAlertInput() = %q, want %q", gotResult, tt.wantResult)
			}
			if gotChanged != tt.wantChanged {
				t.Errorf("SanitizeAlertInput() changed = %v, want %v", gotChanged, tt.wantChanged)
			}
		})
	}
}

// TestSanitizeAlertInputStrict_HTMLSpecialChars tests the strict version with HTML escaping.
func TestSanitizeAlertInputStrict_HTMLSpecialChars(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		maxLen      int
		wantResult  string
		wantChanged bool
	}{
		{
			name:        "angle brackets escaped",
			input:       "<script>alert('xss')</script>",
			maxLen:      255,
			wantResult:  "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
			wantChanged: true,
		},
		{
			name:        "ampersand escaped",
			input:       "test & value",
			maxLen:      255,
			wantResult:  "test &amp; value",
			wantChanged: true,
		},
		{
			name:        "double quotes escaped",
			input:       `test "quoted" value`,
			maxLen:      255,
			wantResult:  "test &#34;quoted&#34; value",
			wantChanged: true,
		},
		{
			name:        "single quotes escaped",
			input:       "test 'single' value",
			maxLen:      255,
			wantResult:  "test &#39;single&#39; value",
			wantChanged: true,
		},
		{
			name:        "combined HTML special chars",
			input:       `<div class="test" data-value='1'>Test & Demo</div>`,
			maxLen:      255,
			wantResult:  "&lt;div class=&#34;test&#34; data-value=&#39;1&#39;&gt;Test &amp; Demo&lt;/div&gt;",
			wantChanged: true,
		},
		{
			name:        "control chars and HTML escaping combined",
			input:       "<script>\nalert('xss')\r</script>",
			maxLen:      255,
			wantResult:  "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
			wantChanged: true,
		},
		{
			name:        "normal string unchanged in strict mode",
			input:       "Hello World 123",
			maxLen:      255,
			wantResult:  "Hello World 123",
			wantChanged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotChanged := SanitizeAlertInputStrict(tt.input, tt.maxLen)
			if gotResult != tt.wantResult {
				t.Errorf("SanitizeAlertInputStrict() = %q, want %q", gotResult, tt.wantResult)
			}
			if gotChanged != tt.wantChanged {
				t.Errorf("SanitizeAlertInputStrict() changed = %v, want %v", gotChanged, tt.wantChanged)
			}
		})
	}
}

// TestTruncateString tests the truncateString helper function.
func TestTruncateString(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		maxLen     int
		wantResult string
	}{
		{
			name:       "shorter string unchanged",
			input:      "short",
			maxLen:     10,
			wantResult: "short",
		},
		{
			name:       "exact length unchanged",
			input:      "exact",
			maxLen:     5,
			wantResult: "exact",
		},
		{
			name:       "longer string truncated",
			input:      "this is a long string",
			maxLen:     10,
			wantResult: "this is a ",
		},
		{
			name:       "empty string",
			input:      "",
			maxLen:     10,
			wantResult: "",
		},
		{
			name:       "ASCII truncation at exact boundary",
			input:      "hello",
			maxLen:     5,
			wantResult: "hello",
		},
		{
			name:       "ASCII truncation shorter than input",
			input:      "hello world",
			maxLen:     5,
			wantResult: "hello",
		},
		{
			name:       "UTF-8 no truncation when under limit",
			input:      "日本語",
			maxLen:     20,
			wantResult: "日本語",
		},
		{
			name:       "UTF-8 exact length",
			input:      "日本語",
			maxLen:     9, // 3 chars * 3 bytes each
			wantResult: "日本語",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult := truncateString(tt.input, tt.maxLen)
			if gotResult != tt.wantResult {
				t.Errorf("truncateString() = %q, want %q", gotResult, tt.wantResult)
			}
		})
	}
}

// TestIsPrintable tests the IsPrintable helper function.
func TestIsPrintable(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantPrint bool
	}{
		{
			name:      "normal string is printable",
			input:     "Hello World!",
			wantPrint: true,
		},
		{
			name:      "string with newline is printable",
			input:     "Hello\nWorld",
			wantPrint: true,
		},
		{
			name:      "string with carriage return is printable",
			input:     "Hello\rWorld",
			wantPrint: true,
		},
		{
			name:      "string with tab is printable",
			input:     "Hello\tWorld",
			wantPrint: true,
		},
		{
			name:      "string with NUL is not printable",
			input:     "Hello\x00World",
			wantPrint: false,
		},
		{
			name:      "string with escape is not printable",
			input:     "Hello\x1bWorld",
			wantPrint: false,
		},
		{
			name:      "unicode is printable",
			input:     "日本語",
			wantPrint: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPrint := IsPrintable(tt.input)
			if gotPrint != tt.wantPrint {
				t.Errorf("IsPrintable() = %v, want %v", gotPrint, tt.wantPrint)
			}
		})
	}
}

// TestRemoveControlChars tests the RemoveControlChars helper function.
func TestRemoveControlChars(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantResult string
	}{
		{
			name:       "removes NUL",
			input:      "test\x00input",
			wantResult: "testinput",
		},
		{
			name:       "removes CR and LF",
			input:      "test\r\ninput",
			wantResult: "testinput",
		},
		{
			name:       "removes tab",
			input:      "test\tinput",
			wantResult: "testinput",
		},
		{
			name:       "removes multiple control chars",
			input:      "\x00\x01test\x02\x03input\x7F",
			wantResult: "testinput",
		},
		{
			name:       "preserves printable chars",
			input:      "test!@#$%^&*()",
			wantResult: "test!@#$%^&*()",
		},
		{
			name:       "preserves unicode",
			input:      "test日本語",
			wantResult: "test日本語",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult := RemoveControlChars(tt.input)
			if gotResult != tt.wantResult {
				t.Errorf("RemoveControlChars() = %q, want %q", gotResult, tt.wantResult)
			}
		})
	}
}

// TestDefaultMaxHostnameLength verifies the default constant.
func TestDefaultMaxHostnameLength(t *testing.T) {
	if DefaultMaxHostnameLength != 255 {
		t.Errorf("DefaultMaxHostnameLength = %d, want 255", DefaultMaxHostnameLength)
	}
}
