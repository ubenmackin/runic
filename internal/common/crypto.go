package common

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateHMACKey returns 32 random bytes (256 bits) hex-encoded as a
// 64-character lowercase string. Despite the name, the output is suitable
// for any symmetric-key purpose that needs a 256-bit secret — HMAC, JWT
// signing, AES-256 keys, etc. The bytes are sourced from crypto/rand and
// should never be reused across distinct deployments.
func GenerateHMACKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
