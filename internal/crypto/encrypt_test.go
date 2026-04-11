package crypto

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestNewEncryptor_Success tests that NewEncryptor creates a valid encryptor
func TestNewEncryptor_Success(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}
	if enc == nil {
		t.Fatal("NewEncryptor() returned nil encryptor")
	}
}

// TestNewEncryptor_EmptyPassphrase tests that NewEncryptor rejects empty passphrase
func TestNewEncryptor_EmptyPassphrase(t *testing.T) {
	_, err := NewEncryptor("")
	if err != ErrEmptyPassphrase {
		t.Errorf("NewEncryptor('') expected ErrEmptyPassphrase, got %v", err)
	}
}

// TestNewEncryptorWithSalt_Success tests creating an encryptor with a known salt
func TestNewEncryptorWithSalt_Success(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() returned unexpected error: %v", err)
	}

	enc, err := NewEncryptorWithSalt("test-passphrase", salt)
	if err != nil {
		t.Fatalf("NewEncryptorWithSalt() returned unexpected error: %v", err)
	}
	if enc == nil {
		t.Fatal("NewEncryptorWithSalt() returned nil encryptor")
	}

	// Verify the salt matches
	retrievedSalt := enc.GetSalt()
	if string(retrievedSalt) != string(salt) {
		t.Error("GetSalt() returned different salt than provided")
	}
}

// TestNewEncryptorWithSalt_InvalidSaltLength tests that invalid salt length is rejected
func TestNewEncryptorWithSalt_InvalidSaltLength(t *testing.T) {
	_, err := NewEncryptorWithSalt("test-passphrase", []byte("short"))
	if err == nil {
		t.Error("NewEncryptorWithSalt() expected error for invalid salt length, got nil")
	}
}

// TestEncryptDecrypt_RoundTrip tests that encryption followed by decryption returns original text
func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	enc, err := NewEncryptor("my-secret-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}

	plaintext := "this is a secret message"
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() returned unexpected error: %v", err)
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() returned unexpected error: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypt() returned %q, want %q", decrypted, plaintext)
	}
}

// TestEncrypt_MultipleCalls tests that multiple encryptions produce different ciphertexts
func TestEncrypt_MultipleCalls(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}

	plaintext := "same message"
	ciphertexts := make(map[string]bool)

	for i := 0; i < 10; i++ {
		ct, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt() iteration %d returned unexpected error: %v", i, err)
		}
		if ciphertexts[ct] {
			t.Errorf("Encrypt() produced duplicate ciphertext on iteration %d", i)
		}
		ciphertexts[ct] = true
	}

	if len(ciphertexts) != 10 {
		t.Errorf("Expected 10 unique ciphertexts, got %d", len(ciphertexts))
	}
}

// TestEncrypt_EmptyPlaintext tests that empty plaintext is rejected
func TestEncrypt_EmptyPlaintext(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}

	_, err = enc.Encrypt("")
	if err != ErrEmptyPlaintext {
		t.Errorf("Encrypt('') expected ErrEmptyPlaintext, got %v", err)
	}
}

// TestDecrypt_EmptyCiphertext tests that empty ciphertext is rejected
func TestDecrypt_EmptyCiphertext(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}

	_, err = enc.Decrypt("")
	if err != ErrEmptyCiphertext {
		t.Errorf("Decrypt('') expected ErrEmptyCiphertext, got %v", err)
	}
}

// TestDecrypt_InvalidBase64 tests that invalid base64 is rejected
func TestDecrypt_InvalidBase64(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}

	_, err = enc.Decrypt("not-valid-base64!!!")
	if err == nil {
		t.Error("Decrypt() expected error for invalid base64, got nil")
	}
}

// TestDecrypt_TooShort tests that too-short ciphertext is rejected
func TestDecrypt_TooShort(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}

	// Create a valid base64 string that's too short
	shortData := base64.StdEncoding.EncodeToString([]byte("short"))

	_, err = enc.Decrypt(shortData)
	if err != ErrInvalidCiphertext {
		t.Errorf("Decrypt() expected ErrInvalidCiphertext, got %v", err)
	}
}

// TestDecrypt_WrongPassphrase tests that decryption fails with wrong passphrase
func TestDecrypt_WrongPassphrase(t *testing.T) {
	enc1, err := NewEncryptor("correct-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}

	ciphertext, err := enc1.Encrypt("secret message")
	if err != nil {
		t.Fatalf("Encrypt() returned unexpected error: %v", err)
	}

	enc2, err := NewEncryptor("wrong-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}

	_, err = enc2.Decrypt(ciphertext)
	if err != ErrDecryptionFailed {
		t.Errorf("Decrypt() with wrong passphrase expected ErrDecryptionFailed, got %v", err)
	}
}

// TestStandaloneEncryptDecrypt tests the standalone Encrypt/Decrypt functions
func TestStandaloneEncryptDecrypt(t *testing.T) {
	plaintext := "standalone secret"
	passphrase := "my-passphrase"

	ciphertext, err := Encrypt(plaintext, passphrase)
	if err != nil {
		t.Fatalf("Encrypt() returned unexpected error: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, passphrase)
	if err != nil {
		t.Fatalf("Decrypt() returned unexpected error: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypt() returned %q, want %q", decrypted, plaintext)
	}
}

// TestStandaloneEncrypt_EmptyPassphrase tests standalone encrypt with empty passphrase
func TestStandaloneEncrypt_EmptyPassphrase(t *testing.T) {
	_, err := Encrypt("test", "")
	if err != ErrEmptyPassphrase {
		t.Errorf("Encrypt() with empty passphrase expected ErrEmptyPassphrase, got %v", err)
	}
}

// TestStandaloneEncrypt_EmptyPlaintext tests standalone encrypt with empty plaintext
func TestStandaloneEncrypt_EmptyPlaintext(t *testing.T) {
	_, err := Encrypt("", "passphrase")
	if err != ErrEmptyPlaintext {
		t.Errorf("Encrypt() with empty plaintext expected ErrEmptyPlaintext, got %v", err)
	}
}

// TestStandaloneDecrypt_EmptyPassphrase tests standalone decrypt with empty passphrase
func TestStandaloneDecrypt_EmptyPassphrase(t *testing.T) {
	_, err := Decrypt("dGVzdA==", "")
	if err != ErrEmptyPassphrase {
		t.Errorf("Decrypt() with empty passphrase expected ErrEmptyPassphrase, got %v", err)
	}
}

// TestStandaloneDecrypt_EmptyCiphertext tests standalone decrypt with empty ciphertext
func TestStandaloneDecrypt_EmptyCiphertext(t *testing.T) {
	_, err := Decrypt("", "passphrase")
	if err != ErrEmptyCiphertext {
		t.Errorf("Decrypt() with empty ciphertext expected ErrEmptyCiphertext, got %v", err)
	}
}

// TestDeriveKey tests key derivation
func TestDeriveKey(t *testing.T) {
	salt := []byte("0123456789abcdef") // 16 bytes
	key1 := DeriveKey("passphrase", salt)
	key2 := DeriveKey("passphrase", salt)

	if len(key1) != keyLength {
		t.Errorf("DeriveKey() returned key of length %d, want %d", len(key1), keyLength)
	}

	// Same passphrase and salt should produce same key
	if string(key1) != string(key2) {
		t.Error("DeriveKey() should produce consistent keys for same input")
	}

	// Different passphrase should produce different key
	key3 := DeriveKey("different-passphrase", salt)
	if string(key1) == string(key3) {
		t.Error("DeriveKey() should produce different keys for different passphrases")
	}

	// Different salt should produce different key
	key4 := DeriveKey("passphrase", []byte("fedcba9876543210"))
	if string(key1) == string(key4) {
		t.Error("DeriveKey() should produce different keys for different salts")
	}
}

// TestGenerateSalt tests salt generation
func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() returned unexpected error: %v", err)
	}

	if len(salt1) != saltLength {
		t.Errorf("GenerateSalt() returned salt of length %d, want %d", len(salt1), saltLength)
	}

	// Multiple calls should produce different salts
	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() returned unexpected error: %v", err)
	}

	if string(salt1) == string(salt2) {
		t.Error("GenerateSalt() should produce unique salts")
	}
}

// TestGetSalt tests retrieving the salt from an encryptor
func TestGetSalt(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}

	salt := enc.GetSalt()
	if len(salt) != saltLength {
		t.Errorf("GetSalt() returned salt of length %d, want %d", len(salt), saltLength)
	}

	// Calling again should return the same salt
	salt2 := enc.GetSalt()
	if string(salt) != string(salt2) {
		t.Error("GetSalt() should return consistent salt")
	}
}

// TestThreadSafety tests concurrent encryption/decryption operations
func TestThreadSafety(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}

	const numGoroutines = 10
	const numOperations = 100

	errors := make(chan error, numGoroutines*numOperations)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numOperations; j++ {
				plaintext := "message"
				ciphertext, err := enc.Encrypt(plaintext)
				if err != nil {
					errors <- err
					return
				}

				decrypted, err := enc.Decrypt(ciphertext)
				if err != nil {
					errors <- err
					return
				}

				if decrypted != plaintext {
					errors <- err
					return
				}
			}
			errors <- nil
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		if err := <-errors; err != nil {
			t.Errorf("Concurrent operation failed: %v", err)
		}
	}
}

// TestCiphertextFormat verifies the ciphertext format
func TestCiphertextFormat(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}

	plaintext := "test"
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() returned unexpected error: %v", err)
	}

	// Verify it's valid base64
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Fatalf("Ciphertext is not valid base64: %v", err)
	}

	// Verify minimum length: salt (16) + nonce (12) + GCM tag (16) + min ciphertext (1)
	minLen := saltLength + nonceLength + 16 + 1
	if len(data) < minLen {
		t.Errorf("Decoded ciphertext length %d is less than minimum %d", len(data), minLen)
	}
}

// TestLongPlaintext tests encryption/decryption of longer plaintexts
func TestLongPlaintext(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}

	// Test with 1KB of data
	plaintext := strings.Repeat("x", 1024)
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() returned unexpected error: %v", err)
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() returned unexpected error: %v", err)
	}

	if decrypted != plaintext {
		t.Error("Decrypt() failed to return original long plaintext")
	}
}

// TestEncryptorReuse tests that an encryptor can be reused multiple times
func TestEncryptorReuse(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}

	for i := 0; i < 100; i++ {
		plaintext := "message"
		ciphertext, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt() iteration %d returned unexpected error: %v", i, err)
		}

		decrypted, err := enc.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt() iteration %d returned unexpected error: %v", i, err)
		}

		if decrypted != plaintext {
			t.Errorf("Decrypt() iteration %d returned %q, want %q", i, decrypted, plaintext)
		}
	}
}
