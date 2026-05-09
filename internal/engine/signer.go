package engine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func Version(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

func Sign(content string, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(content))
	return hex.EncodeToString(mac.Sum(nil))
}

func Verify(content string, key string, signature string) bool {
	expected := Sign(content, key)
	return hmac.Equal([]byte(expected), []byte(signature))
}
