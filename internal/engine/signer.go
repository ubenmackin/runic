package engine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Version computes the SHA256 of the rules content and returns it as hex.
func Version(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// Sign computes an HMAC-SHA256 of the rules content using the provided key.
func Sign(content string, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(content))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify returns true if the HMAC of content matches the provided signature.
func Verify(content string, key string, signature string) bool {
	expected := Sign(content, key)
	return hmac.Equal([]byte(expected), []byte(signature))
}
