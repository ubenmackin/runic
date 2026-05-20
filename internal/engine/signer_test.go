package engine

import (
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		content string
		key     string
	}{
		{
			name:    "simple rules content",
			content: "*filter\n-A INPUT -j ACCEPT\nCOMMIT\n",
			key:     "test-key-123",
		},
		{
			name:    "empty content",
			content: "",
			key:     "another-key",
		},
		{
			name:    "complex rules with multiple chains",
			content: "*filter\n:INPUT DROP [0:0]\n:OUTPUT DROP [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n",
			key:     "hmac-key-abc",
		},
		{
			name:    "unicode content",
			content: "# Firewall rules\n*filter\n-A INPUT -j ACCEPT\n",
			key:     "key-with-unicode-🔐",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := Sign(tt.content, tt.key)
			if !Verify(tt.content, tt.key, sig, 0) {
				t.Errorf("Sign(%q, %q) produced signature that failed Verify", tt.content, tt.key)
			}
		})
	}
}

func TestVerifyRejectsTamperedContent(t *testing.T) {
	tests := []struct {
		name     string
		original string
		tampered string
		key      string
	}{
		{
			name:     "single character change",
			original: "*filter\n-A INPUT -j ACCEPT\n",
			tampered: "*filter\n-A INPUT -j DROP\n",
			key:      "test-key",
		},
		{
			name:     "added character",
			original: "original content",
			tampered: "original content!",
			key:      "another-key",
		},
		{
			name:     "removed character",
			original: "firewall rules content",
			tampered: "firewall rules conten",
			key:      "key123",
		},
		{
			name:     "completely different content",
			original: "first set of rules",
			tampered: "second set of rules",
			key:      "key456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := Sign(tt.original, tt.key)
			if Verify(tt.tampered, tt.key, sig, 0) {
				t.Errorf("Verify(%q, %q, sig) returned true for tampered content", tt.tampered, tt.key)
			}
		})
	}
}

func TestSignProducesNonEmptySignature(t *testing.T) {
	tests := []struct {
		name    string
		content string
		key     string
	}{
		{
			name:    "short content",
			content: "x",
			key:     "key",
		},
		{
			name:    "empty content",
			content: "",
			key:     "key",
		},
		{
			name:    "typical rules",
			content: "*filter\n-A INPUT -j ACCEPT\nCOMMIT\n",
			key:     "my-secret-key",
		},
		{
			name:    "very long content",
			content: "rule1\nrule2\nrule3\nrule4\nrule5\nrule6\nrule7\nrule8\nrule9\nrule10\n",
			key:     "long-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := Sign(tt.content, tt.key)
			if sig == "" {
				t.Errorf("Sign(%q, %q) returned empty signature", tt.content, tt.key)
			}
			// Signature should be hex-encoded, so it should only contain hex characters
			for _, c := range sig {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("Sign(%q, %q) returned non-hex signature: %q", tt.content, tt.key, sig)
					break
				}
			}
		})
	}
}

func TestDifferentKeysProduceDifferentSignatures(t *testing.T) {
	content := "*filter\n-A INPUT -j ACCEPT\nCOMMIT\n"
	keys := []string{
		"key-one",
		"key-two",
		"different-key",
		"completely-different",
	}

	// Collect all signatures
	sigs := make(map[string]bool)
	for _, key := range keys {
		sig := Sign(content, key)
		if sigs[sig] {
			t.Errorf("Duplicate signature produced for key %q", key)
		}
		sigs[sig] = true
	}

	// Verify we got unique signatures for each key
	if len(sigs) != len(keys) {
		t.Errorf("Expected %d unique signatures, got %d", len(keys), len(sigs))
	}

	// Verify that each key's signature validates correctly but others don't
	for _, key := range keys {
		sig := Sign(content, key)
		if !Verify(content, key, sig, 0) {
			t.Errorf("Signature for key %q failed self-verification", key)
		}
		// Verify that signature from one key fails with another key
		for _, otherKey := range keys {
			if otherKey != key {
				if Verify(content, otherKey, sig, 0) {
					t.Errorf("Signature from key %q validated with different key %q", key, otherKey)
				}
			}
		}
	}
}

func TestVersion(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "empty content",
			content: "",
		},
		{
			name:    "simple rules",
			content: "*filter\n-A INPUT -j ACCEPT\n",
		},
		{
			name:    "multiline rules",
			content: "*filter\n:INPUT DROP [0:0]\n:OUTPUT DROP [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A OUTPUT -p tcp --sport 22 -j ACCEPT\nCOMMIT\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := Version(tt.content)
			if v == "" {
				t.Errorf("Version(%q) returned empty string", tt.content)
			}
			// Version should be hex-encoded SHA256 (64 characters for 32 bytes)
			if len(v) != 64 {
				t.Errorf("Version(%q) returned hash of length %d, expected 64", tt.content, len(v))
			}
		})
	}
}

func TestVersionDeterministic(t *testing.T) {
	content := "test content for hashing"

	v1 := Version(content)
	v2 := Version(content)

	if v1 != v2 {
		t.Errorf("Version(%q) is not deterministic: got %q then %q", content, v1, v2)
	}
}

func TestVersionDifferentContent(t *testing.T) {
	tests := []struct {
		name1 string
		c1    string
		name2 string
		c2    string
	}{
		{
			name1: "first content",
			c1:    "first content",
			name2: "second content",
			c2:    "second content",
		},
		{
			name1: "single char diff",
			c1:    "contentA",
			name2: "contentB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name1+"_vs_"+tt.name2, func(t *testing.T) {
			v1 := Version(tt.c1)
			v2 := Version(tt.c2)
			if v1 == v2 {
				t.Errorf("Version produced same hash for different content")
			}
		})
	}
}

// TestVerify_UsesSignWithVersion is a regression test for the bug where
// Verify() called Sign() instead of SignWithVersion(), causing versioned
// payloads to always be verified against version 0 regardless of the
// versionNumber argument. If Verify() were still using Sign(), then
// Verify(content, key, sig, 5) would internally compute the signature for
// version 0 and succeed — which would be wrong.
func TestVerify_UsesSignWithVersion(t *testing.T) {
	content := "*filter\n-A INPUT -j ACCEPT\nCOMMIT\n"
	key := "regression-test-key"
	version := 5

	// Sign the content with a specific non-zero version number.
	sig := SignWithVersion(content, key, version)

	// Verify() must succeed when called with the SAME version number.
	if !Verify(content, key, sig, version) {
		t.Errorf("Verify() returned false for signature created with version %d; expected true", version)
	}

	// Verify() must fail when called with a DIFFERENT version number.
	// If Verify() incorrectly used Sign() (version 0) internally, this
	// would still pass for version 0 — so we also check a wrong version
	// that is NOT 0 to catch both the v0-vs-v5 and v1-vs-v5 cases.
	wrongVersion := version + 1
	if Verify(content, key, sig, wrongVersion) {
		t.Errorf("Verify() returned true for signature created with version %d when verified with version %d; expected false (Verify may be using Sign instead of SignWithVersion)", version, wrongVersion)
	}

	// Additionally, verifying against version 0 must fail because the
	// signature was created with a non-zero version.
	if Verify(content, key, sig, 0) {
		t.Errorf("Verify() returned true for signature created with version %d when verified with version 0; expected false (Verify may be using Sign instead of SignWithVersion)", version)
	}
}

func TestVerify_VersionedSignature(t *testing.T) {
	content := "*filter\n-A INPUT -j ACCEPT\nCOMMIT\n"
	key := "test-hmac-key"

	// Create a version-1 signature using SignWithVersion
	sigV1 := SignWithVersion(content, key, 1)

	// Verify with version 1 should succeed
	if !Verify(content, key, sigV1, 1) {
		t.Error("Verify failed for version-1 signature with version=1")
	}

	// Verify with version 0 should fail (version mismatch)
	if Verify(content, key, sigV1, 0) {
		t.Error("Verify succeeded for version-1 signature with version=0 (expected failure)")
	}

	// Create a version-0 signature using SignWithVersion
	sigV0 := SignWithVersion(content, key, 0)

	// Verify with version 0 should succeed
	if !Verify(content, key, sigV0, 0) {
		t.Error("Verify failed for version-0 signature with version=0")
	}

	// Verify with version 1 should fail (version mismatch)
	if Verify(content, key, sigV0, 1) {
		t.Error("Verify succeeded for version-0 signature with version=1 (expected failure)")
	}

	// Verify that version-0 and version-1 signatures are different
	if sigV0 == sigV1 {
		t.Error("Version-0 and version-1 signatures are identical (expected different)")
	}
}
