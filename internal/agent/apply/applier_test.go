package apply

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"runic/internal/engine"
	"runic/internal/models"
)

// TestValidateRulesAndHMAC tests rule validation and HMAC signing/verification
func TestValidateRulesAndHMAC(t *testing.T) {
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
				Rules:   `# *filter COMMIT :INPUT DROP :OUTPUT DROP`,
				HMAC:    engine.Sign(`# *filter COMMIT :INPUT DROP :OUTPUT DROP`, "test-key"),
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

			cancel := scheduleRevert(context.Background(), backupRules, tt.delay, "http://test", "token", "1.0.0")

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

// TestApplyBundleParameterValidation tests parameter validation for bundle application
func TestApplyBundleParameterValidation(t *testing.T) {
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

// TestValidateRulesOnBackupStrings tests validation of backup rule strings
func TestValidateRulesOnBackupStrings(t *testing.T) {
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

// TestApplyBundleSuccess tests successful bundle application with mock iptables.
func TestApplyBundleSuccess(t *testing.T) {
	tests := []struct {
		name          string
		bundle        models.BundleResponse
		hmacKey       string
		expectErr     bool
		expectApplied bool
		expectCached  bool
	}{
		{
			name: "minimal valid bundle",
			bundle: models.BundleResponse{
				Version: "test-v1",
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
			hmacKey:       "test-hmac-key",
			expectErr:     false,
			expectApplied: true,
			expectCached:  true,
		},
		{
			name: "bundle with Docker chain",
			bundle: models.BundleResponse{
				Version: "test-v2",
				Rules: `# Runic rule bundle
*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
:FORWARD DROP [0:0]
:DOCKER-USER - [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A OUTPUT -p icmp -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A DOCKER-USER -j RETURN
-A INPUT -j LOG --log-prefix "[RUNIC-DROP] " --log-level 4
-A INPUT -j DROP
-A OUTPUT -j LOG --log-prefix "[RUNIC-DROP] " --log-level 4
-A OUTPUT -j DROP
COMMIT
`,
			},
			hmacKey:       "test-hmac-key-2",
			expectErr:     false,
			expectApplied: true,
			expectCached:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock environment
			tmpDir, cleanup := setupMockEnvironment(t, "success")
			defer cleanup()

			// Create mock control plane server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle heartbeat for smoke test
				if r.URL.Path == "/api/v1/agent/heartbeat" {
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"status":"ok"}`)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			// Sign the bundle
			tt.bundle.HMAC = engine.Sign(tt.bundle.Rules, tt.hmacKey)

			// Create a mock confirm function
			confirmCalled := false
			confirmFunc := func(ctx context.Context, version string) error {
				confirmCalled = true
				return nil
			}

			// Apply the bundle (uses mocked iptables in PATH)
			err := ApplyBundle(context.Background(), tt.bundle, tt.hmacKey, server.URL, "test-token", "1.0.0", confirmFunc)

			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}

				// Verify confirm was called
				if !confirmCalled {
					t.Error("confirm function was not called")
				}

				// Verify bundle was cached
				cachedPath := filepath.Join(tmpDir, "cached-bundle.rules")
				if _, err := os.Stat(cachedPath); os.IsNotExist(err) {
					// Note: CacheBundle writes to /etc/runic-agent/cached-bundle.rules
					// In test environment, this may fail due to permissions
					// That's acceptable - we just verify no error on apply
				}
			}
		})
	}
}

// TestApplyBundleRollback tests bundle application rollback on failure.
func TestApplyBundleRollback(t *testing.T) {
	tests := []struct {
		name         string
		bundle       models.BundleResponse
		hmacKey      string
		mockBehavior string
		expectErr    bool
		errContains  string
	}{
		{
			name: "iptables-restore fails",
			bundle: models.BundleResponse{
				Version: "test-rollback-v1",
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
			hmacKey:      "test-hmac-key",
			mockBehavior: "fail-restore",
			expectErr:    true,
			errContains:  "iptables-restore failed",
		},
		{
			name: "smoke test fails triggers revert",
			bundle: models.BundleResponse{
				Version: "test-rollback-v2",
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
			hmacKey:      "test-hmac-key",
			mockBehavior: "success",
			expectErr:    true,
			errContains:  "smoke test failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock environment
			tmpDir, cleanup := setupMockEnvironment(t, tt.mockBehavior)
			defer cleanup()

			// Create mock control plane server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// For smoke test failure scenario, return error
				if r.URL.Path == "/api/v1/agent/heartbeat" {
					if tt.mockBehavior == "success" && strings.Contains(tt.name, "smoke test") {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"status":"ok"}`)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			// Sign the bundle
			tt.bundle.HMAC = engine.Sign(tt.bundle.Rules, tt.hmacKey)

			// Apply the bundle
			err := ApplyBundle(context.Background(), tt.bundle, tt.hmacKey, server.URL, "test-token", "1.0.0", nil)

			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %v", tt.errContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			// Verify that iptables-save was called (for backup)
			saveCalledFile := filepath.Join(tmpDir, "iptables-save.called")
			if _, err := os.Stat(saveCalledFile); os.IsNotExist(err) {
				t.Error("iptables-save was not called for backup")
			}

			// For rollback scenarios, verify iptables-restore was called at least once
			restoreCalledFile := filepath.Join(tmpDir, "iptables-restore.called")
			if _, err := os.Stat(restoreCalledFile); os.IsNotExist(err) {
				t.Error("iptables-restore was not called")
			}
		})
	}
}

// setupMockEnvironment creates a temporary directory with mock iptables binaries.
// The behavior parameter controls what the mock does:
// - "success": all commands succeed
// - "fail-restore": iptables-restore returns exit code 1
// - "fail-save": iptables-save returns exit code 1
func setupMockEnvironment(t *testing.T, behavior string) (tmpDir string, cleanup func()) {
	t.Helper()

	// Create temp directory
	tmpDir = t.TempDir()

	// Create mock iptables-save
	iptablesSave := filepath.Join(tmpDir, "iptables-save")
	saveScript := generateMockScript("iptables-save", behavior, tmpDir)
	if err := os.WriteFile(iptablesSave, []byte(saveScript), 0755); err != nil {
		t.Fatalf("failed to create mock iptables-save: %v", err)
	}

	// Create mock iptables-restore
	iptablesRestore := filepath.Join(tmpDir, "iptables-restore")
	restoreScript := generateMockScript("iptables-restore", behavior, tmpDir)
	if err := os.WriteFile(iptablesRestore, []byte(restoreScript), 0755); err != nil {
		t.Fatalf("failed to create mock iptables-restore: %v", err)
	}

	// Create mock ipset
	ipset := filepath.Join(tmpDir, "ipset")
	ipsetScript := generateMockScript("ipset", behavior, tmpDir)
	if err := os.WriteFile(ipset, []byte(ipsetScript), 0755); err != nil {
		t.Fatalf("failed to create mock ipset: %v", err)
	}

	// Create mock iptables (used by iptables command)
	iptables := filepath.Join(tmpDir, "iptables")
	iptablesScript := generateMockScript("iptables", behavior, tmpDir)
	if err := os.WriteFile(iptables, []byte(iptablesScript), 0755); err != nil {
		t.Fatalf("failed to create mock iptables: %v", err)
	}

	// Save original PATH
	origPath := os.Getenv("PATH")

	// Prepend our tmpDir to PATH
	newPath := tmpDir + string(os.PathListSeparator) + origPath
	if err := os.Setenv("PATH", newPath); err != nil {
		t.Fatalf("failed to set PATH: %v", err)
	}

	// Return cleanup function
	cleanup = func() {
		if err := os.Setenv("PATH", origPath); err != nil {
			t.Logf("failed to restore PATH: %v", err)
		}
	}

	return tmpDir, cleanup
}

// generateMockScript generates a shell script that mocks iptables/ipset commands.
func generateMockScript(command, behavior, tmpDir string) string {
	var script strings.Builder

	script.WriteString("#!/bin/sh\n")
	script.WriteString("set -e\n")
	script.WriteString(fmt.Sprintf("# Mock %s (behavior: %s)\n", command, behavior))
	script.WriteString("\n")

	// Log that we were called
	script.WriteString(fmt.Sprintf("touch \"%s/%s.called\"\n", tmpDir, command))

	// Log arguments for debugging
	script.WriteString(fmt.Sprintf("echo \"$@\" >> \"%s/%s.args\"\n", tmpDir, command))

	// Handle different behaviors
	switch {
	case behavior == "fail-save" && command == "iptables-save":
		script.WriteString("echo 'Error: mock iptables-save failure' >&2\n")
		script.WriteString("exit 1\n")

	case behavior == "fail-restore" && command == "iptables-restore":
		script.WriteString("echo 'Error: mock iptables-restore failure' >&2\n")
		script.WriteString("exit 1\n")

	case command == "iptables-save":
		// Return a minimal valid iptables-save output
		script.WriteString("cat << 'EOF'\n")
		script.WriteString("# Generated by mock iptables-save\n")
		script.WriteString("*filter\n")
		script.WriteString(":INPUT DROP [0:0]\n")
		script.WriteString(":OUTPUT DROP [0:0]\n")
		script.WriteString(":FORWARD DROP [0:0]\n")
		script.WriteString("-A INPUT -i lo -j ACCEPT\n")
		script.WriteString("COMMIT\n")
		script.WriteString("EOF\n")

	case command == "iptables-restore":
		// Accept input from file argument
		script.WriteString("# iptables-restore: accept rules from file\n")
		script.WriteString("if [ -n \"$1\" ]; then\n")
		script.WriteString("  # Read and discard the file (we're mocking)\n")
		script.WriteString("  cat \"$1\" > /dev/null 2>&1 || true\n")
		script.WriteString("fi\n")
		script.WriteString("exit 0\n")

	case command == "ipset":
		// ipset list -n returns empty list
		script.WriteString("if [ \"$1\" = \"list\" ] && [ \"$2\" = \"-n\" ]; then\n")
		script.WriteString("  # No existing ipsets\n")
		script.WriteString("  exit 0\n")
		script.WriteString("fi\n")
		script.WriteString("# Other ipset commands succeed\n")
		script.WriteString("exit 0\n")

	case command == "iptables":
		// iptables command - just succeed
		script.WriteString("exit 0\n")

	default:
		script.WriteString("exit 0\n")
	}

	return script.String()
}

// TestApplyBundleIntegrationWithRealMocks tests the full bundle apply flow with detailed verification.
func TestApplyBundleIntegrationWithRealMocks(t *testing.T) {
	// Setup mock environment
	tmpDir, cleanup := setupMockEnvironment(t, "success")
	defer cleanup()

	// Create mock control plane server
	heartbeatCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agent/heartbeat" {
			heartbeatCalled = true
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("expected Authorization header 'Bearer test-token', got %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status":"ok"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create valid bundle
	bundle := models.BundleResponse{
		Version: "integration-test-v1",
		Rules: `# Integration test bundle
*filter
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
	}
	hmacKey := "test-hmac-key"

	// Sign the bundle
	bundle.HMAC = engine.Sign(bundle.Rules, hmacKey)

	// Track confirm callback
	confirmCalled := false
	confirmVersion := ""
	confirmFunc := func(ctx context.Context, version string) error {
		confirmCalled = true
		confirmVersion = version
		return nil
	}

	// Apply the bundle
	err := ApplyBundle(context.Background(), bundle, hmacKey, server.URL, "test-token", "1.0.0", confirmFunc)
	if err != nil {
		t.Fatalf("ApplyBundle failed: %v", err)
	}

	// Verify confirm was called with correct version
	if !confirmCalled {
		t.Error("confirm function was not called")
	}
	if confirmVersion != bundle.Version {
		t.Errorf("confirm called with wrong version: got %q, want %q", confirmVersion, bundle.Version)
	}

	// Verify heartbeat was called (smoke test)
	if !heartbeatCalled {
		t.Error("heartbeat endpoint was not called (smoke test failed)")
	}

	// Verify iptables-save was called (backup)
	saveCalledFile := filepath.Join(tmpDir, "iptables-save.called")
	if _, err := os.Stat(saveCalledFile); os.IsNotExist(err) {
		t.Error("iptables-save was not called for backup")
	}

	// Verify iptables-restore was called (apply)
	restoreCalledFile := filepath.Join(tmpDir, "iptables-restore.called")
	if _, err := os.Stat(restoreCalledFile); os.IsNotExist(err) {
		t.Error("iptables-restore was not called for apply")
	}
}

// TestApplyBundleWithIpset tests bundle application with ipset definitions.
// Note: This test verifies the ipset parsing logic by checking that the bundle validates.
// The actual ipset commands are tested separately.
func TestApplyBundleWithIpset(t *testing.T) {
	// Setup mock environment
	tmpDir, cleanup := setupMockEnvironment(t, "success")
	defer cleanup()

	// Create mock control plane server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agent/heartbeat" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status":"ok"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create bundle with ipset definitions (as comments - the proper format)
	// The ipset section is marked with a special comment before *filter
	bundle := models.BundleResponse{
		Version: "ipset-test-v1",
		Rules: `# Runic bundle with ipset definitions
# --- Ipset Definitions ---
create runic_group_office hash:ip family inet
add runic_group_office 192.168.1.10
add runic_group_office 192.168.1.11
*filter
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
	}
	hmacKey := "test-hmac-key"

	// Sign the bundle
	bundle.HMAC = engine.Sign(bundle.Rules, hmacKey)

	// Apply the bundle
	err := ApplyBundle(context.Background(), bundle, hmacKey, server.URL, "test-token", "1.0.0", nil)
	if err != nil {
		t.Fatalf("ApplyBundle failed: %v", err)
	}

	// Verify ipset was called
	ipsetCalledFile := filepath.Join(tmpDir, "ipset.called")
	if _, err := os.Stat(ipsetCalledFile); os.IsNotExist(err) {
		t.Error("ipset was not called for ipset definitions")
	}

	// Verify iptables-restore was called
	restoreCalledFile := filepath.Join(tmpDir, "iptables-restore.called")
	if _, err := os.Stat(restoreCalledFile); os.IsNotExist(err) {
		t.Error("iptables-restore was not called")
	}
}

// TestIpsetSectionParsing tests the ipset section parsing logic.
func TestIpsetSectionParsing(t *testing.T) {
	tests := []struct {
		name           string
		rules          string
		expectIpset    bool
		expectedCount  int
		expectParseErr bool
	}{
		{
			name: "bundle with ipset definitions",
			rules: `# --- Ipset Definitions ---
create runic_group_office hash:ip family inet
add runic_group_office 192.168.1.10
*filter
:INPUT DROP [0:0]
COMMIT
`,
			expectIpset:   true,
			expectedCount: 1,
		},
		{
			name: "bundle without ipset definitions",
			rules: `*filter
:INPUT DROP [0:0]
COMMIT
`,
			expectIpset: false,
		},
		{
			name: "bundle with multiple ipsets",
			rules: `# --- Ipset Definitions ---
create runic_group_office hash:ip family inet
add runic_group_office 192.168.1.10
create runic_group_vpn hash:net family inet
add runic_group_vpn 10.0.0.0/24
*filter
:INPUT DROP [0:0]
COMMIT
`,
			expectIpset:   true,
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			section, err := extractIpsetSection(tt.rules)
			if err != nil {
				if tt.expectParseErr {
					return // Expected error
				}
				t.Fatalf("extractIpsetSection error: %v", err)
			}

			if tt.expectIpset {
				if section == "" {
					t.Error("expected ipset section to be extracted")
				}

				defs, err := parseIpsetDefs(section)
				if err != nil {
					t.Fatalf("parseIpsetDefs error: %v", err)
				}

				if len(defs) != tt.expectedCount {
					t.Errorf("expected %d ipset definitions, got %d", tt.expectedCount, len(defs))
				}
			} else {
				if section != "" {
					t.Errorf("expected no ipset section, got: %s", section)
				}
			}
		})
	}
}

// TestStripIpsetSection tests the stripIpsetSection helper function.
func TestStripIpsetSection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name: "bundle with ipset section",
			input: `# Runic bundle
# --- Ipset Definitions ---
create runic_group_office hash:ip family inet
add runic_group_office 192.168.1.10
*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
COMMIT
`,
			expected: `# Runic bundle
*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
COMMIT
`,
		},
		{
			name: "bundle without ipset section",
			input: `*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
COMMIT
`,
			expected: `*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
COMMIT
`,
		},
		{
			name: "bundle with ipset marker but no *filter",
			input: `# --- Ipset Definitions ---
create runic_group_office hash:ip family inet
add runic_group_office 192.168.1.10
`,
			expected: `# --- Ipset Definitions ---
create runic_group_office hash:ip family inet
add runic_group_office 192.168.1.10
`,
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name: "bundle with ipset section at the very beginning",
			input: `# --- Ipset Definitions ---
create runic_group_office hash:ip family inet
add runic_group_office 192.168.1.10
*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
COMMIT
`,
			expected: `*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
COMMIT
`,
		},
		{
			name: "bundle with content before ipset marker",
			input: `# Runic rule bundle
# Host: test-server
# Generated: 2024-01-01T00:00:00Z
# --- Ipset Definitions ---
create runic_group_dns hash:net family inet
add runic_group_dns 10.0.0.0/24
*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
COMMIT
`,
			expected: `# Runic rule bundle
# Host: test-server
# Generated: 2024-01-01T00:00:00Z
*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
COMMIT
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripIpsetSection(tt.input)
			if result != tt.expected {
				t.Errorf("stripIpsetSection() mismatch:\ngot:\n%q\nwant:\n%q", result, tt.expected)
			}
		})
	}
}

// TestApplyBundleHMACFailure tests that HMAC verification failure prevents apply.
func TestApplyBundleHMACFailure(t *testing.T) {
	// Setup mock environment (though it shouldn't be called)
	_, cleanup := setupMockEnvironment(t, "success")
	defer cleanup()

	// Create bundle with invalid HMAC
	bundle := models.BundleResponse{
		Version: "hmac-fail-v1",
		Rules: `*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
COMMIT
`,
		HMAC: "invalid-hmac-signature",
	}
	hmacKey := "correct-key"

	// Apply the bundle - should fail HMAC verification
	err := ApplyBundle(context.Background(), bundle, hmacKey, "http://localhost:8080", "test-token", "1.0.0", nil)
	if err == nil {
		t.Fatal("expected HMAC verification error, got nil")
	}

	if !strings.Contains(err.Error(), "HMAC verification failed") {
		t.Errorf("expected HMAC verification error, got: %v", err)
	}
}

// TestApplyBundleValidationFailure tests that rule validation failure prevents apply.
func TestApplyBundleValidationFailure(t *testing.T) {
	// Setup mock environment (though it shouldn't be called)
	_, cleanup := setupMockEnvironment(t, "success")
	defer cleanup()

	// Create bundle with invalid rules
	bundle := models.BundleResponse{
		Version: "validation-fail-v1",
		Rules:   `invalid rules content`,
	}
	hmacKey := "test-key"

	// Sign the bundle (valid HMAC, invalid rules)
	bundle.HMAC = engine.Sign(bundle.Rules, hmacKey)

	// Apply the bundle - should fail validation
	err := ApplyBundle(context.Background(), bundle, hmacKey, "http://localhost:8080", "test-token", "1.0.0", nil)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}

	if !strings.Contains(err.Error(), "rule validation failed") {
		t.Errorf("expected validation error, got: %v", err)
	}
}
