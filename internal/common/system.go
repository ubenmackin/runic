package common

import "os/exec"

// DetectIPSet returns true if the ipset binary is available on PATH.
func DetectIPSet() bool {
	_, err := exec.LookPath("ipset")
	return err == nil
}
