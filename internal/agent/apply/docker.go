package apply

import (
	"context"
	"os/exec"
	"strings"
	"sync"

	"runic/internal/common"
)

var (
	hasDockerOnce   sync.Once
	hasDockerCached bool
)

func hasDocker() bool {
	hasDockerOnce.Do(func() {
		if common.DetectDockerSocket() {
			hasDockerCached = true
			return
		}
		_, err := exec.LookPath("docker")
		if err != nil {
			hasDockerCached = false
			return
		}
		out, err := exec.Command("systemctl", "is-active", "docker").Output()
		hasDockerCached = err == nil && strings.TrimSpace(string(out)) == "active"
	})
	return hasDockerCached
}

func restartDocker(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "systemctl", "restart", "docker")
	return cmd.Run()
}
