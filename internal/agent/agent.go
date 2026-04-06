// Package agent provides core device functionality.
package agent

import (
	"runic/internal/agent/core"
	"runic/internal/agent/identity"
)

// Re-export for backward compatibility

// Agent is the main agent struct.
type Agent = core.Agent

// Config holds the agent configuration.
type Config = identity.Config

// New creates a new Agent instance.
func New(configPath, controlPlaneURL string) *Agent {
	return core.New(configPath, controlPlaneURL)
}
