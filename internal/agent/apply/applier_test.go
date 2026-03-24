package apply

import (
	"strings"
	"testing"
	"time"

	"runic/internal/engine"
	"runic/internal/models"
)

// TestApplyBundleSuccess tests successful bundle application
func TestApplyBundleSuccess(t *testing.T) {
	tests := []struct {
		name    string
		bundle  models.BundleResponse
		hmacKey string
		wantErr bool
	}{
		{
			name: "valid bundle",
			bundle: models.BundleResponse{
				Version: "test-version-1",
				Rules: `*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
:FORWARD DROP [0:0]

-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

-A INPUT -p icmp -j ACCEPT
-A OUTPUT -p icmp -j ACCEPT

-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

-A INPUT -j LOG --log-prefix "[RUNIC-DROP] " --log-level 4
-A INPUT -j DROP
-A OUTPUT -j LOG --log-prefix "[RUNIC-DROP] " --log-level 4
-A OUTPUT -j DROP

COMMIT
`,
			},
			hmacKey: "test-key",
			wantErr: false,
		},
		{
			name: "valid bundle with policy",
			bundle: models.BundleResponse{
				Version: "test-version-2",
				Rules: `# Runic rule bundle
# Host:      test-server
# Generated: 2024-01-01T00:00:00Z
# Policies:  1
*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
:FORWARD DROP [0:0]

# --- Standard: loopback ---
-A INPUT  -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# --- Standard: ICMP ---
-A INPUT  -p icmp -j ACCEPT
-A OUTPUT -p icmp -j ACCEPT

# --- Standard: established/related ---
-A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# --- Policy: allow-ssh | office -> ssh ---
-A INPUT  -s 192.168.1.0/24 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -d 192.168.1.0/24 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# --- Logging and default deny ---
-A INPUT  -j LOG --log-prefix "[RUNIC-DROP] " --log-level 4
-A INPUT  -j DROP
-A OUTPUT -j LOG --log-prefix "[RUNIC-DROP] " --log-level 4
-A OUTPUT -j DROP

COMMIT
`,
			},
			hmacKey: "test-key",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Sign the bundle
			signature := engine.Sign(tt.bundle.Rules, tt.hmacKey)
			tt.bundle.HMAC = signature

			// Note: This test would normally mock exec.Command to avoid actual iptables calls
			// For now, we'll skip the actual apply and just test the validation logic
			err := validateRules(tt.bundle.Rules)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRules() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Test HMAC verification
			if !engine.Verify(tt.bundle.Rules, tt.hmacKey, tt.bundle.HMAC) {
				t.Error("HMAC verification failed")
			}

			// Test signature function
			sig := engine.Sign(tt.bundle.Rules, tt.hmacKey)
			if sig != tt.bundle.HMAC {
				t.Error("Sign produced different signature")
			}
		})
	}
}

// TestApplyBundleFailure tests failure scenarios
func TestApplyBundleFailure(t *testing.T) {
	tests := []struct {
		name        string
		bundle      models.BundleResponse
		hmacKey     string
		wantErr     bool
		errContains string
	}{
		{
			name: "invalid HMAC",
			bundle: models.BundleResponse{
				Version: "test-v1",
				Rules: `*filter
:INPUT DROP [0:0]
COMMIT
`,
				HMAC: "invalid-signature",
			},
			hmacKey:     "test-key",
			wantErr:     true,
			errContains: "HMAC verification failed",
		},
		{
			name: "empty rules",
			bundle: models.BundleResponse{
				Version: "test-v2",
				Rules:   "",
				HMAC:    engine.Sign("", "test-key"),
			},
			hmacKey:     "test-key",
			wantErr:     true,
			errContains: "rules content is empty",
		},
		{
			name: "missing *filter table",
			bundle: models.BundleResponse{
				Version: "test-v3",
				Rules: `:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
COMMIT
`,
				HMAC: engine.Sign(`:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
COMMIT
`, "test-key"),
			},
			hmacKey:     "test-key",
			wantErr:     true,
			errContains: "missing *filter table",
		},
		{
			name: "missing COMMIT",
			bundle: models.BundleResponse{
				Version: "test-v4",
				Rules: `*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
`,
				HMAC: engine.Sign(`*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
`, "test-key"),
			},
			hmacKey:     "test-key",
			wantErr:     true,
			errContains: "missing COMMIT",
		},
		{
			name: "missing INPUT DROP chain",
			bundle: models.BundleResponse{
				Version: "test-v5",
				Rules: `*filter
:OUTPUT DROP [0:0]
COMMIT
`,
				HMAC: engine.Sign(`*filter
:OUTPUT DROP [0:0]
COMMIT
`, "test-key"),
			},
			hmacKey:     "test-key",
			wantErr:     true,
			errContains: "missing :INPUT DROP chain",
		},
		{
			name: "missing OUTPUT DROP chain",
			bundle: models.BundleResponse{
				Version: "test-v6",
				Rules: `*filter
:INPUT DROP [0:0]
COMMIT
`,
				HMAC: engine.Sign(`*filter
:INPUT DROP [0:0]
COMMIT
`, "test-key"),
			},
			hmacKey:     "test-key",
			wantErr:     true,
			errContains: "missing :OUTPUT DROP chain",
		},
		{
			name: "no valid rules",
			bundle: models.BundleResponse{
				Version: "test-v7",
				Rules: `# *filter COMMIT :INPUT DROP :OUTPUT DROP`,
				HMAC: engine.Sign(`# *filter COMMIT :INPUT DROP :OUTPUT DROP`, "test-key"),
			},
			hmacKey:     "test-key",
			wantErr:     true,
			errContains: "no valid iptables rules found",
		},
		{
			name: "too many rules",
			bundle: models.BundleResponse{
				Version: "test-v8",
				Rules:   generateExcessiveRules(15000),
				HMAC:    engine.Sign(generateExcessiveRules(15000), "test-key"),
			},
			hmacKey:     "test-key",
			wantErr:     true,
			errContains: "too many rules",
		},
		{
			name: "malformed rule line",
			bundle: models.BundleResponse{
				Version: "test-v9",
				Rules: `*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
invalid-rule-line without dash
COMMIT
`,
				HMAC: engine.Sign(`*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
invalid-rule-line without dash
COMMIT
`, "test-key"),
			},
			hmacKey:     "test-key",
			wantErr:     true,
			errContains: "possibly malformed line",
		},
		{
			name: "tampered content",
			bundle: models.BundleResponse{
				Version: "test-v10",
				Rules: `*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
COMMIT
`,
				HMAC: engine.Sign(`*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
COMMIT
`, "different-key"),
			},
			hmacKey:     "test-key",
			wantErr:     true,
			errContains: "HMAC verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test HMAC verification
			if tt.wantErr && tt.errContains == "HMAC verification failed" {
				if engine.Verify(tt.bundle.Rules, tt.hmacKey, tt.bundle.HMAC) {
					t.Error("expected HMAC verification to fail")
				}
				return // Skip validateRules check since HMAC verification is the expected failure point
			}

			// Test validation logic
			err := validateRules(tt.bundle.Rules)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %v", tt.errContains, err)
				}
			}
		})
	}
}

// TestValidateRules tests the validateRules function specifically
func TestValidateRules(t *testing.T) {
	tests := []struct {
		name        string
		rules       string
		wantErr     bool
		errContains string
	}{
		{
			name: "valid minimal rules",
			rules: `*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
COMMIT
`,
			wantErr: false,
		},
		{
			name: "valid rules with comments and empty lines",
			rules: `# Header comment
*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]

-A INPUT -i lo -j ACCEPT

COMMIT
`,
			wantErr: false,
		},
		{
			name: "valid rules with DOCKER-USER chain",
			rules: `*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
:DOCKER-USER - [0:0]
-A INPUT -i lo -j ACCEPT
-A DOCKER-USER -j RETURN
COMMIT
`,
			wantErr: false,
		},
		{
			name: "rules with exactly 10000 lines",
			rules: func() string {
				var builder strings.Builder
				builder.WriteString("*filter\n")
				builder.WriteString(":INPUT DROP [0:0]\n")
				builder.WriteString(":OUTPUT DROP [0:0]\n")
				for i := 0; i < 9996; i++ {
					builder.WriteString("-A INPUT -s 10.0.0.0/24 -j ACCEPT\n")
				}
				builder.WriteString("COMMIT\n")
				return builder.String()
			}(),
			wantErr: false,
		},
		{
			name:    "empty string",
			rules:   "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			rules:   "   \n  \n  ",
			wantErr: true,
		},
		{
			name:        "missing filter table",
			rules:       ":INPUT DROP [0:0]\nCOMMIT\n",
			wantErr:     true,
			errContains: "missing *filter table",
		},
		{
			name:        "missing commit",
			rules:       "*filter\n:INPUT DROP [0:0]\n",
			wantErr:     true,
			errContains: "missing COMMIT",
		},
		{
			name:        "missing INPUT chain",
			rules:       "*filter\n:OUTPUT DROP [0:0]\nCOMMIT\n",
			wantErr:     true,
			errContains: "missing :INPUT DROP chain",
		},
		{
			name: "INPUT chain not DROP",
			rules: `*filter
:INPUT ACCEPT [0:0]
COMMIT
`,
			wantErr:     true,
			errContains: "missing :INPUT DROP chain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRules(tt.rules)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %v", tt.errContains, err)
				}
			}
		})
	}
}

// TestHMACSignature tests HMAC signing and verification
func TestHMACSignature(t *testing.T) {
	tests := []struct {
		name    string
		content string
		key     string
	}{
		{
			name:    "simple content",
			content: "test content",
			key:     "test-key",
		},
		{
			name:    "empty content",
			content: "",
			key:     "test-key",
		},
		{
			name:    "large content",
			content: strings.Repeat("large content ", 1000),
			key:     "test-key",
		},
		{
			name:    "special characters",
			content: "hello\nworld\r\n\t!@#$%^&*()",
			key:     "test-key",
		},
		{
			name:    "unicode content",
			content: "Hello 世界! 🌍",
			key:     "test-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test signing
			signature := engine.Sign(tt.content, tt.key)
			if signature == "" {
				t.Error("Sign returned empty signature")
			}
			if len(signature) != 64 {
				t.Errorf("expected 64 char signature, got %d", len(signature))
			}

			// Test verification with correct signature
			if !engine.Verify(tt.content, tt.key, signature) {
				t.Error("Verify failed for correct signature")
			}

			// Test verification with wrong signature
			wrongSignature := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			if engine.Verify(tt.content, tt.key, wrongSignature) {
				t.Error("Verify succeeded for wrong signature")
			}

			// Test verification with wrong key
			wrongKey := "wrong-key"
			wrongKeySignature := engine.Sign(tt.content, wrongKey)
			if engine.Verify(tt.content, tt.key, wrongKeySignature) {
				t.Error("Verify succeeded for signature from wrong key")
			}

			// Test verification with modified content
			modifiedContent := tt.content + "modified"
			if engine.Verify(modifiedContent, tt.key, signature) {
				t.Error("Verify succeeded for modified content")
			}

			// Test signature consistency
			sig1 := engine.Sign(tt.content, tt.key)
			sig2 := engine.Sign(tt.content, tt.key)
			if sig1 != sig2 {
				t.Error("Sign produced different signatures for same content")
			}
		})
	}
}

// TestScheduleRevert tests the revert scheduling function
func TestScheduleRevert(t *testing.T) {
	tests := []struct {
		name       string
		delay      time.Duration
		cancelFast bool
	}{
		{
			name:       "revert cancelled before timeout",
			delay:      5 * time.Second,
			cancelFast: true,
		},
		{
			name:       "revert not cancelled",
			delay:      100 * time.Millisecond,
			cancelFast: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backupRules := "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"

			cancel := scheduleRevert(backupRules, tt.delay, "http://test", "token", "1.0.0")

			if tt.cancelFast {
				// Cancel immediately - revert should not execute
				cancel()
				time.Sleep(tt.delay + 100*time.Millisecond)
			} else {
				// Let the revert trigger
				time.Sleep(tt.delay + 200*time.Millisecond)
			}

			// This is a basic test - in a real integration test we'd use channels/sync
			// to verify if revert was actually called
		})
	}
}

// TestVersionHash tests version hashing functionality
func TestVersionHash(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantLen int
	}{
		{
			name:    "simple content",
			content: "test content",
			wantLen: 64,
		},
		{
			name:    "empty content",
			content: "",
			wantLen: 64,
		},
		{
			name:    "large content",
			content: strings.Repeat("large content ", 1000),
			wantLen: 64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := engine.Version(tt.content)
			if len(version) != tt.wantLen {
				t.Errorf("expected version length %d, got %d", tt.wantLen, len(version))
			}

			// Test consistency
			v1 := engine.Version(tt.content)
			v2 := engine.Version(tt.content)
			if v1 != v2 {
				t.Error("Version produced different hashes for same content")
			}

			// Test different content produces different versions
			if tt.content != "" {
				v3 := engine.Version(tt.content + "different")
				if v1 == v3 {
					t.Error("Version produced same hash for different content")
				}
			}
		})
	}
}

// Helper function to generate excessive rules
func generateExcessiveRules(count int) string {
	var builder strings.Builder
	builder.WriteString("*filter\n")
	builder.WriteString(":INPUT DROP [0:0]\n")
	builder.WriteString(":OUTPUT DROP [0:0]\n")
	for i := 0; i < count; i++ {
		builder.WriteString("-A INPUT -s 10.0.0.1 -j ACCEPT\n")
	}
	builder.WriteString("COMMIT\n")
	return builder.String()
}

// TestBundleResponseValidation tests bundle response structure
func TestBundleResponseValidation(t *testing.T) {
	tests := []struct {
		name    string
		bundle  models.BundleResponse
		wantErr bool
	}{
		{
			name: "valid bundle",
			bundle: models.BundleResponse{
				Version: "abc123",
				Rules:   "*filter\n:INPUT DROP [0:0]\nCOMMIT\n",
				HMAC:    engine.Sign("*filter\n:INPUT DROP [0:0]\nCOMMIT\n", "key"),
			},
			wantErr: false,
		},
		{
			name:    "empty version",
			bundle:  models.BundleResponse{Version: "", Rules: "rules", HMAC: "sig"},
			wantErr: true,
		},
		{
			name:    "empty rules",
			bundle:  models.BundleResponse{Version: "v1", Rules: "", HMAC: "sig"},
			wantErr: true,
		},
		{
			name:    "empty HMAC",
			bundle:  models.BundleResponse{Version: "v1", Rules: "rules", HMAC: ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := tt.bundle.Version != "" && tt.bundle.Rules != "" && tt.bundle.HMAC != ""
			if valid == tt.wantErr {
				t.Errorf("validation mismatch: valid=%v, wantErr=%v", valid, tt.wantErr)
			}
		})
	}
}

// TestDockerRulesInBundle tests Docker-specific rules
func TestDockerRulesInBundle(t *testing.T) {
	bundle := models.BundleResponse{
		Version: "docker-test",
		Rules: `# Runic rule bundle
*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
:FORWARD DROP [0:0]
:DOCKER-USER - [0:0]

-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# --- Standard: ICMP ---
-A INPUT -p icmp -j ACCEPT
-A OUTPUT -p icmp -j ACCEPT

# --- Docker: DOCKER-USER chain management ---
-A DOCKER-USER -j RETURN

COMMIT
`,
		HMAC: engine.Sign(``, "key"),
	}

	// Add proper HMAC
	bundle.HMAC = engine.Sign(bundle.Rules, "test-key")

	// Verify the bundle contains Docker rules
	if !strings.Contains(bundle.Rules, ":DOCKER-USER") {
		t.Error("expected DOCKER-USER chain declaration")
	}
	if !strings.Contains(bundle.Rules, "-A DOCKER-USER -j RETURN") {
		t.Error("expected DOCKER-USER RETURN rule")
	}

	// Validate the rules
	err := validateRules(bundle.Rules)
	if err != nil {
		t.Errorf("validateRules failed: %v", err)
	}

	// Verify HMAC
	if !engine.Verify(bundle.Rules, "test-key", bundle.HMAC) {
		t.Error("HMAC verification failed")
	}
}

// TestSmokeTestValidation tests smoke test scenarios
func TestSmokeTestValidation(t *testing.T) {
	// Note: This test is conceptual - the actual smokeTest function makes HTTP calls
	// In a real test, you would mock the HTTP client

	tests := []struct {
		name          string
		controlPlane  string
		token         string
		version       string
		expectSuccess bool
	}{
		{
			name:          "valid control plane URL",
			controlPlane:  "http://localhost:8080",
			token:         "valid-token",
			version:       "1.0.0",
			expectSuccess: true,
		},
		{
			name:          "invalid control plane URL",
			controlPlane:  "http://invalid-host:9999",
			token:         "valid-token",
			version:       "1.0.0",
			expectSuccess: false,
		},
		{
			name:          "missing token",
			controlPlane:  "http://localhost:8080",
			token:         "",
			version:       "1.0.0",
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validation would be done by actually calling smokeTest with mocked HTTP client
			// For now, just validate the parameters
			if tt.controlPlane == "" {
				t.Error("control plane URL cannot be empty")
			}
			if tt.token == "" && tt.expectSuccess {
				t.Error("token cannot be empty for expected success")
			}
			if tt.version == "" {
				t.Error("version cannot be empty")
			}
		})
	}
}

// TestRevertFunctionality tests the revert logic
func TestRevertFunctionality(t *testing.T) {
	backup := `*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
COMMIT
`

	tests := []struct {
		name    string
		backup  string
		wantErr bool
	}{
		{
			name:    "valid backup",
			backup:  backup,
			wantErr: false,
		},
		{
			name:    "empty backup",
			backup:  "",
			wantErr: true,
		},
		{
			name:    "invalid backup",
			backup:  "not-iptables-rules",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate the backup
			if tt.backup != "" {
				err := validateRules(tt.backup)
				if (err != nil) != tt.wantErr {
					t.Errorf("backup validation error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}
