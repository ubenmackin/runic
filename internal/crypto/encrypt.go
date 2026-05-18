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

	// gcmTagSize is the size of the GCM authentication tag in bytes (128 bits = 16 bytes)
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

// Encryptor provides AES-256-GCM encryption with PBKDF2 key derivation. It caches the derived key to avoid recomputing PBKDF2 on each operation.
type Encryptor struct {
	mu         sync.RWMutex
	passphrase string
	key        []byte
	// salt stores the initial salt generated at construction time.
	// It is exposed via GetSalt() for callers that need to persist the salt
	// alongside encrypted data. Each Encrypt/Decrypt call derives a fresh
	// salt independently (embedded in the ciphertext), so this field is
	// optional metadata and not used for crypto operations.
	salt []byte
}

// NewEncryptor creates a new Encryptor from a passphrase. The passphrase is used to derive an AES-256 key using PBKDF2.
// A random salt is generated for key derivation if not provided.
func NewEncryptor(passphrase string) (*Encryptor, error) {
	if passphrase == "" {
		return nil, ErrEmptyPassphrase
	}

	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, keyLength, sha256.New)

	return &Encryptor{
		passphrase: passphrase,
		key:        key,
		salt:       salt,
	}, nil
}

// GetSalt returns the salt used for key derivation. This can be stored alongside encrypted data for later decryption.
func (e *Encryptor) GetSalt() []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()

	salt := make([]byte, len(e.salt))
	copy(salt, e.salt)
	return salt
}

// Encrypt encrypts plaintext using AES-256-GCM. The ciphertext format is: base64(salt || nonce || ciphertext)
// This function is thread-safe. A fresh random salt is generated for each encryption call.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", ErrEmptyPlaintext
	}

	e.mu.RLock()
	passphrase := e.passphrase
	e.mu.RUnlock()

	return encryptWithPassphrase(plaintext, passphrase)
}

// Decrypt decrypts ciphertext using AES-256-GCM. The ciphertext must be in the format: base64(salt || nonce || ciphertext)
// This function is thread-safe.
func (e *Encryptor) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", ErrEmptyCiphertext
	}

	e.mu.RLock()
	passphrase := e.passphrase
	e.mu.RUnlock()

	return decryptWithPassphrase(ciphertext, passphrase)
}

// DeriveKey derives an AES-256 key from a passphrase and salt using PBKDF2. This is a standalone function for when you need to derive a key without
// creating an Encryptor instance.
func DeriveKey(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, keyLength, sha256.New)
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// encryptWithPassphrase is the shared internal helper for AES-256-GCM encryption with PBKDF2 key derivation.
// Both Encryptor.Encrypt() and Encrypt() delegate to this function.
func encryptWithPassphrase(plaintext, passphrase string) (string, error) {
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

	key := DeriveKey(passphrase, salt)

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

	// Combine salt + nonce + ciphertext
	result := make([]byte, 0, saltLength+nonceLength+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return base64.StdEncoding.EncodeToString(result), nil
}

// decryptWithPassphrase is the shared internal helper for AES-256-GCM decryption with PBKDF2 key derivation.
// Both Encryptor.Decrypt() and Decrypt() delegate to this function.
func decryptWithPassphrase(ciphertext, passphrase string) (string, error) {
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

	key := DeriveKey(passphrase, salt)

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

// Encrypt encrypts plaintext using AES-256-GCM with PBKDF2 key derivation. This is a standalone function for one-off encryption operations.
// Returns base64-encoded ciphertext in format: base64(salt || nonce || ciphertext)
func Encrypt(plaintext string, passphrase string) (string, error) {
	return encryptWithPassphrase(plaintext, passphrase)
}

// Decrypt decrypts ciphertext using AES-256-GCM with PBKDF2 key derivation. This is a standalone function for one-off decryption operations.
// Expects ciphertext in format: base64(salt || nonce || ciphertext)
func Decrypt(ciphertext string, passphrase string) (string, error) {
	return decryptWithPassphrase(ciphertext, passphrase)
}
