package common

import (
	"os/exec"
	"testing"
)

// TestDetectIPSetBehavior verifies the behavior of DetectIPSet
// by comparing with a direct exec.LookPath call.
func TestDetectIPSetBehavior(t *testing.T) {
	// Get the result from DetectIPSet
	result := DetectIPSet()

	// Get the result from direct exec.LookPath call
	_, err := exec.LookPath("ipset")
	expectedResult := err == nil

	// Both should return the same result
	if result != expectedResult {
		t.Errorf("DetectIPSet() = %v, want %v (from exec.LookPath)", result, expectedResult)
	}
}

// TestDetectIPSetConsistency verifies the function returns consistent results
// across multiple calls.
func TestDetectIPSetConsistency(t *testing.T) {
	// Call DetectIPSet multiple times
	results := make([]bool, 5)
	for i := 0; i < 5; i++ {
		results[i] = DetectIPSet()
	}

	// All results should be identical
	for i := 1; i < 5; i++ {
		if results[i] != results[0] {
			t.Errorf("DetectIPSet() returned inconsistent results: %v vs %v", results[0], results[i])
		}
	}
}
