// Package crypto provides AES-256-GCM encryption utilities for encrypting
// sensitive data such as SMTP passwords and other secrets.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// keyLength is the length of the AES-256 key in bytes (256 bits = 32 bytes)
	keyLength = 32

	// saltLength is the length of the salt used in PBKDF2 key derivation
	saltLength = 16

	// nonceLength is the length of the GCM nonce (96 bits = 12 bytes)
	nonceLength = 12

	// gcmTagSize is the size of the GCM authentication tag in bytes (128 bits = 16 bytes).
	// Used as part of the minimum-length check on decoded ciphertext.
	gcmTagSize = 16
)

// pbkdf2Iterations is the number of iterations for PBKDF2 key derivation.
// Default is 600,000 as recommended by OWASP for PBKDF2-SHA256.
// This is a variable so it can be overridden in tests for performance.
var pbkdf2Iterations = 600000

// Errors returned by encryption and decryption operations
var (
	ErrEmptyPassphrase   = errors.New("passphrase cannot be empty")
	ErrEmptyPlaintext    = errors.New("plaintext cannot be empty")
	ErrEmptyCiphertext   = errors.New("ciphertext cannot be empty")
	ErrInvalidCiphertext = errors.New("invalid ciphertext: too short")
	ErrDecryptionFailed  = errors.New("decryption failed: authentication tag mismatch")
)

// Encryptor provides AES-256-GCM encryption with PBKDF2 key derivation. The
// derived key is cached at construction time so subsequent Encrypt / Decrypt
// calls do not pay the PBKDF2 cost on every operation.
//
// Ciphertext format produced by Encryptor.Encrypt: base64(nonce || ciphertext).
// This is intentionally different from the package-level Encrypt helper, which
// embeds a per-call salt (see its doc comment).
type Encryptor struct {
	mu  sync.RWMutex
	key []byte
}

// NewEncryptor creates a new Encryptor from a passphrase. The passphrase is
// used to derive an AES-256 key with PBKDF2; the resulting key is cached and
// reused for the lifetime of the Encryptor. The derivation salt is generated
// once with crypto/rand and discarded after derivation — the derived key
// alone is what the Encryptor retains.
func NewEncryptor(passphrase string) (*Encryptor, error) {
	if passphrase == "" {
		return nil, ErrEmptyPassphrase
	}

	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}

	key := deriveKey(passphrase, salt)

	return &Encryptor{key: key}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the cached key.
// Returns base64(nonce || ciphertext). Thread-safe.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", ErrEmptyPlaintext
	}

	e.mu.RLock()
	key := e.key
	e.mu.RUnlock()

	return encryptWithKey(plaintext, key)
}

// Decrypt decrypts ciphertext using AES-256-GCM with the cached key.
// Expects ciphertext in format: base64(nonce || ciphertext). Thread-safe.
func (e *Encryptor) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", ErrEmptyCiphertext
	}

	e.mu.RLock()
	key := e.key
	e.mu.RUnlock()

	return decryptWithKey(ciphertext, key)
}

// GenerateSalt returns a fresh cryptographically random salt of saltLength
// bytes, suitable for PBKDF2 key derivation.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// deriveKey derives an AES-256 key from a passphrase and salt using PBKDF2.
func deriveKey(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, keyLength, sha256.New)
}

// encryptWithKey performs AES-256-GCM encryption with a pre-derived key and
// returns base64(nonce || ciphertext).
func encryptWithKey(plaintext string, key []byte) (string, error) {
	if len(key) == 0 {
		return "", ErrEmptyPassphrase
	}
	if plaintext == "" {
		return "", ErrEmptyPlaintext
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, nonceLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	result := make([]byte, 0, nonceLength+len(ciphertext))
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return base64.StdEncoding.EncodeToString(result), nil
}

// decryptWithKey performs AES-256-GCM decryption with a pre-derived key.
// Expects base64(nonce || ciphertext).
func decryptWithKey(ciphertext string, key []byte) (string, error) {
	if len(key) == 0 {
		return "", ErrEmptyPassphrase
	}
	if ciphertext == "" {
		return "", ErrEmptyCiphertext
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Minimum length: nonce (12) + GCM tag (16) = 28 bytes.
	minLength := nonceLength + gcmTagSize
	if len(data) < minLength {
		return "", ErrInvalidCiphertext
	}

	nonce := data[:nonceLength]
	actualCiphertext := data[nonceLength:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	return string(plaintext), nil
}

// Encrypt encrypts plaintext using AES-256-GCM with PBKDF2 key derivation.
// This is a standalone helper for one-off encryption operations that need a
// self-contained ciphertext (e.g. database migrations).
//
// Ciphertext format: base64(salt || nonce || ciphertext). A fresh random salt
// is generated for every call. Use Decrypt with the same passphrase to
// recover the plaintext.
//
// NOTE: This format is incompatible with Encryptor.Encrypt, which produces
// base64(nonce || ciphertext) using a cached key.
func Encrypt(plaintext string, passphrase string) (string, error) {
	if passphrase == "" {
		return "", ErrEmptyPassphrase
	}
	if plaintext == "" {
		return "", ErrEmptyPlaintext
	}

	salt, err := GenerateSalt()
	if err != nil {
		return "", err
	}

	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, nonceLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	result := make([]byte, 0, saltLength+nonceLength+len(sealed))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, sealed...)

	return base64.StdEncoding.EncodeToString(result), nil
}

// Decrypt decrypts ciphertext produced by Encrypt using the same passphrase.
// Expects ciphertext in format: base64(salt || nonce || ciphertext).
func Decrypt(ciphertext string, passphrase string) (string, error) {
	if passphrase == "" {
		return "", ErrEmptyPassphrase
	}
	if ciphertext == "" {
		return "", ErrEmptyCiphertext
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	minLength := saltLength + nonceLength + gcmTagSize
	if len(data) < minLength {
		return "", ErrInvalidCiphertext
	}

	salt := data[:saltLength]
	nonce := data[saltLength : saltLength+nonceLength]
	actualCiphertext := data[saltLength+nonceLength:]

	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	return string(plaintext), nil
}
