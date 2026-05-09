// Package agent provides core device functionality.
package agent

import (
	"runic/internal/agent/core"
	"runic/internal/agent/identity"
)

// Re-export for backward compatibility

type Agent = core.Agent

type Config = identity.Config

func New(configPath, controlPlaneURL string) *Agent {
	return core.New(configPath, controlPlaneURL)
}
