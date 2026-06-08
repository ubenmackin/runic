package engine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

func Version(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// DeriveHMACKey derives a purpose-specific HMAC key using HKDF.
// This provides key separation: the signing key for rule bundles is
// derived from the peer's raw HMAC key with a context-specific salt,
// so the raw key cannot be used for other purposes.
func DeriveHMACKey(rawKey string, purpose string, versionNumber int) []byte {
	salt := []byte(purpose)
	info := []byte(fmt.Sprintf("runic-%s-v%d", purpose, versionNumber))
	reader := hkdf.New(sha256.New, []byte(rawKey), salt, info)
	derived := make([]byte, 32)
	if _, err := reader.Read(derived); err != nil {
		// Fall back to SHA256 of raw key if HKDF fails (should never happen)
		h := sha256.Sum256([]byte(rawKey))
		return h[:]
	}
	return derived
}

// Sign is a thin wrapper that signs content with version number 0.
// It is kept for backwards compatibility with callers that don't track
// explicit bundle versions (e.g. legacy tests in internal/agent/apply).
// New code should call SignWithVersion directly.
func Sign(content string, key string) string {
	return SignWithVersion(content, key, 0)
}

func SignWithVersion(content string, key string, versionNumber int) string {
	derivedKey := DeriveHMACKey(key, "rule-bundle", versionNumber)
	payload := fmt.Sprintf("%d:%s", versionNumber, content)
	mac := hmac.New(sha256.New, derivedKey)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify is a thin wrapper that defers to VerifyWithVersion. The two had
// identical bodies historically; consolidating them removes the duplicate
// signature computation site.
func Verify(content string, key string, signature string, versionNumber int) bool {
	return VerifyWithVersion(content, key, signature, versionNumber)
}

func VerifyWithVersion(content string, key string, signature string, versionNumber int) bool {
	expected := SignWithVersion(content, key, versionNumber)
	return hmac.Equal([]byte(expected), []byte(signature))
}
