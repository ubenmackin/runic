package common

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateHMACKey generates a cryptographically secure random HMAC key.
// Returns a 64-character hex-encoded string (32 bytes).
func GenerateHMACKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
