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
	keyHash := sha256.Sum256([]byte(rawKey))
	salt := make([]byte, 0, len(keyHash)+len(purpose))
	salt = append(salt, keyHash[:]...)
	salt = append(salt, []byte(purpose)...)
	info := []byte(fmt.Sprintf("runic-%s-v%d", purpose, versionNumber))
	return deriveWithSalt(rawKey, salt, info)
}

// deriveLegacyHMACKey derives a key with the legacy salt (purpose only).
// Bundles signed before the salt was bound to the key hash use this
// derivation. It is retained so VerifyWithVersion can accept pre-existing
// bundles and deployed agents keep receiving valid pushes.
func deriveLegacyHMACKey(rawKey string, purpose string, versionNumber int) []byte {
	salt := []byte(purpose)
	info := []byte(fmt.Sprintf("runic-%s-v%d", purpose, versionNumber))
	return deriveWithSalt(rawKey, salt, info)
}

func deriveWithSalt(rawKey string, salt, info []byte) []byte {
	reader := hkdf.New(sha256.New, []byte(rawKey), salt, info)
	derived := make([]byte, 32)
	if _, err := reader.Read(derived); err != nil {
		// Fall back to SHA256 of raw key if HKDF fails (should never happen)
		h := sha256.Sum256([]byte(rawKey))
		return h[:]
	}
	return derived
}

func signWithDerivedKey(content string, derivedKey []byte, versionNumber int) string {
	payload := fmt.Sprintf("%d:%s", versionNumber, content)
	mac := hmac.New(sha256.New, derivedKey)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// signWithLegacyVersion signs content with the legacy key derivation.
// It exists only to support the verification fallback in VerifyWithVersion.
func signWithLegacyVersion(content string, key string, versionNumber int) string {
	derivedKey := deriveLegacyHMACKey(key, "rule-bundle", versionNumber)
	return signWithDerivedKey(content, derivedKey, versionNumber)
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
	return signWithDerivedKey(content, derivedKey, versionNumber)
}

// Verify is a thin wrapper that defers to VerifyWithVersion. The two had
// identical bodies historically; consolidating them removes the duplicate
// signature computation site.
func Verify(content string, key string, signature string, versionNumber int) bool {
	return VerifyWithVersion(content, key, signature, versionNumber)
}

// VerifyWithVersion verifies a bundle signature. It accepts signatures
// created with the current derivation and, for backwards compatibility
// with bundles signed before the salt change, signatures created with
// the legacy derivation (salt was purpose only). New bundles are always
// signed with the current derivation; the legacy path is verify-only so
// existing bundles and deployed agents are not invalidated.
func VerifyWithVersion(content string, key string, signature string, versionNumber int) bool {
	providedBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	for _, expected := range []string{
		SignWithVersion(content, key, versionNumber),
		signWithLegacyVersion(content, key, versionNumber),
	} {
		expectedBytes, err := hex.DecodeString(expected)
		if err != nil {
			continue
		}
		if hmac.Equal(expectedBytes, providedBytes) {
			return true
		}
	}
	return false
}
