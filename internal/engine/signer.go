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
	hkdf := hkdf.New(sha256.New, []byte(rawKey), salt, info)
	derived := make([]byte, 32)
	if _, err := hkdf.Read(derived); err != nil {
		// Fall back to SHA256 of raw key if HKDF fails (should never happen)
		h := sha256.Sum256([]byte(rawKey))
		return h[:]
	}
	return derived
}

func Sign(content string, key string) string {
	derivedKey := DeriveHMACKey(key, "rule-bundle", 0)
	payload := fmt.Sprintf("%d:%s", 0, content)
	mac := hmac.New(sha256.New, derivedKey)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func SignWithVersion(content string, key string, versionNumber int) string {
	derivedKey := DeriveHMACKey(key, "rule-bundle", versionNumber)
	payload := fmt.Sprintf("%d:%s", versionNumber, content)
	mac := hmac.New(sha256.New, derivedKey)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func Verify(content string, key string, signature string, versionNumber int) bool {
	expected := SignWithVersion(content, key, versionNumber)
	return hmac.Equal([]byte(expected), []byte(signature))
}

func VerifyWithVersion(content string, key string, signature string, versionNumber int) bool {
	expected := SignWithVersion(content, key, versionNumber)
	return hmac.Equal([]byte(expected), []byte(signature))
}
