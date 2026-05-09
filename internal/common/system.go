package common

import "os/exec"

func DetectIPSet() bool {
	_, err := exec.LookPath("ipset")
	return err == nil
}
