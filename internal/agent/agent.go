// Package agent is a backward-compatibility shim that re-exports types
// from core and identity. New code should import those packages directly.
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
