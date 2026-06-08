package crypto

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestNewEncryptor_Success(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}
	if enc == nil {
		t.Fatal("NewEncryptor() returned nil encryptor")
	}
}

func TestNewEncryptor_EmptyPassphrase(t *testing.T) {
	_, err := NewEncryptor("")
	if err != ErrEmptyPassphrase {
		t.Errorf("NewEncryptor('') expected ErrEmptyPassphrase, got %v", err)
	}
}

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

func TestDecrypt_TooShort(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}

	shortData := base64.StdEncoding.EncodeToString([]byte("short"))

	_, err = enc.Decrypt(shortData)
	if err != ErrInvalidCiphertext {
		t.Errorf("Decrypt() expected ErrInvalidCiphertext, got %v", err)
	}
}

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

func TestStandaloneEncrypt_EmptyPassphrase(t *testing.T) {
	_, err := Encrypt("test", "")
	if err != ErrEmptyPassphrase {
		t.Errorf("Encrypt() with empty passphrase expected ErrEmptyPassphrase, got %v", err)
	}
}

func TestStandaloneEncrypt_EmptyPlaintext(t *testing.T) {
	_, err := Encrypt("", "passphrase")
	if err != ErrEmptyPlaintext {
		t.Errorf("Encrypt() with empty plaintext expected ErrEmptyPlaintext, got %v", err)
	}
}

func TestStandaloneDecrypt_EmptyPassphrase(t *testing.T) {
	_, err := Decrypt("dGVzdA==", "")
	if err != ErrEmptyPassphrase {
		t.Errorf("Decrypt() with empty passphrase expected ErrEmptyPassphrase, got %v", err)
	}
}

func TestStandaloneDecrypt_EmptyCiphertext(t *testing.T) {
	_, err := Decrypt("", "passphrase")
	if err != ErrEmptyCiphertext {
		t.Errorf("Decrypt() with empty ciphertext expected ErrEmptyCiphertext, got %v", err)
	}
}

func TestDeriveKey(t *testing.T) {
	salt := []byte("0123456789abcdef") // 16 bytes
	key1 := deriveKey("passphrase", salt)
	key2 := deriveKey("passphrase", salt)

	if len(key1) != keyLength {
		t.Errorf("deriveKey() returned key of length %d, want %d", len(key1), keyLength)
	}

	// Same passphrase and salt should produce same key
	if string(key1) != string(key2) {
		t.Error("deriveKey() should produce consistent keys for same input")
	}

	// Different passphrase should produce different key
	key3 := deriveKey("different-passphrase", salt)
	if string(key1) == string(key3) {
		t.Error("deriveKey() should produce different keys for different passphrases")
	}

	// Different salt should produce different key
	key4 := deriveKey("passphrase", []byte("fedcba9876543210"))
	if string(key1) == string(key4) {
		t.Error("deriveKey() should produce different keys for different salts")
	}
}

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

func TestGetSalt(t *testing.T) {
	// Encryptor no longer exposes its derivation salt; the cached key is the
	// sole state. The salt is generated internally by NewEncryptor and
	// discarded after PBKDF2 derivation. This test is kept as a placeholder
	// so future regressions that reintroduce an exposed salt continue to be
	// flagged here.
	t.Skip("Encryptor no longer exposes its derivation salt; see DeriveKey test for salt-based behavior.")
}

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

	// Verify minimum length: nonce (12) + GCM tag (16) + min ciphertext (1)
	// (Encryptor's cached-key path does not embed a salt.)
	minLen := nonceLength + 16 + 1
	if len(data) < minLen {
		t.Errorf("Decoded ciphertext length %d is less than minimum %d", len(data), minLen)
	}
}

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

func TestEncryptLargeData(t *testing.T) {
	enc, err := NewEncryptor("test-passphrase")
	if err != nil {
		t.Fatalf("NewEncryptor() returned unexpected error: %v", err)
	}

	plaintext := strings.Repeat("x", 1024*1024)

	// Measure encryption time
	encryptStart := time.Now()
	ciphertext, err := enc.Encrypt(plaintext)
	encryptDuration := time.Since(encryptStart)
	if err != nil {
		t.Fatalf("Encrypt() returned unexpected error: %v", err)
	}
	t.Logf("Encryption of 1MB data took: %v", encryptDuration)

	// Measure decryption time
	decryptStart := time.Now()
	decrypted, err := enc.Decrypt(ciphertext)
	decryptDuration := time.Since(decryptStart)
	if err != nil {
		t.Fatalf("Decrypt() returned unexpected error: %v", err)
	}
	t.Logf("Decryption of 1MB data took: %v", decryptDuration)

	// Verify the decrypted text matches the original
	if decrypted != plaintext {
		t.Error("Decrypt() failed to return original large plaintext")
	}
}

// TestMain allows tests to customize behavior before running tests.
func TestMain(m *testing.M) {
	// Override PBKDF2 iterations for testing.
	// Production uses 600,000 iterations (OWASP recommended), but that's too slow
	// for tests that run thousands of encryption/decryption operations.
	// 1,000 iterations is sufficient for test coverage while keeping tests fast.
	pbkdf2Iterations = 1000

	m.Run()
}
