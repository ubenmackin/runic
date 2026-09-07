package common

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GeneratePushJobID mints an unpredictable push-job ID (job_<hex16>) using
// crypto/rand. Predictable time-based IDs would let an observer guess
// concurrent job IDs and subscribe to another job's SSE event stream,
// disclosing peer hostnames and push progress.
func GeneratePushJobID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate push job ID: %w", err)
	}
	return "job_" + hex.EncodeToString(b[:]), nil
}
