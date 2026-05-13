package common

import (
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
