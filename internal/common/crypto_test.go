package common

import (
	"regexp"
	"testing"
)

func TestGenerateHMACKey_Success(t *testing.T) {
	key, err := GenerateHMACKey()
	if err != nil {
		t.Fatalf("GenerateHMACKey() returned unexpected error: %v", err)
	}
	if key == "" {
		t.Error("GenerateHMACKey() returned empty string")
	}
}

func TestGenerateHMACKey_Length(t *testing.T) {
	key, err := GenerateHMACKey()
	if err != nil {
		t.Fatalf("GenerateHMACKey() returned unexpected error: %v", err)
	}
	if len(key) != 64 {
		t.Errorf("GenerateHMACKey() returned key of length %d, want 64", len(key))
	}
}

func TestGenerateHMACKey_HexFormat(t *testing.T) {
	key, err := GenerateHMACKey()
	if err != nil {
		t.Fatalf("GenerateHMACKey() returned unexpected error: %v", err)
	}

	hexPattern := regexp.MustCompile("^[0-9a-f]{64}$")
	if !hexPattern.MatchString(key) {
		t.Errorf("GenerateHMACKey() returned key %q, want 64 lowercase hex characters", key)
	}
}

func TestGenerateHMACKey_Uniqueness(t *testing.T) {
	keys := make(map[string]bool)
	iterations := 100

	for i := 0; i < iterations; i++ {
		key, err := GenerateHMACKey()
		if err != nil {
			t.Fatalf("GenerateHMACKey() iteration %d returned unexpected error: %v", i, err)
		}
		if keys[key] {
			t.Errorf("GenerateHMACKey() returned duplicate key %q on iteration %d", key, i)
		}
		keys[key] = true
	}
}
