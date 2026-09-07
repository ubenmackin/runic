package common

import (
	"os"
	"os/exec"
	"sync"
)

var (
	ipsetDetected bool
	ipsetOnce     sync.Once
)

func DetectIPSet() bool {
	ipsetOnce.Do(func() {
		_, err := exec.LookPath("ipset")
		ipsetDetected = err == nil
	})
	return ipsetDetected
}

// DetectDockerSocket reports whether the Docker socket exists at
// /var/run/docker.sock. It is shared by agent registration and bundle
// application so both observe identical Docker presence.
func DetectDockerSocket() bool {
	fi, err := os.Stat("/var/run/docker.sock")
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSocket != 0
}
