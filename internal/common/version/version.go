// Package version provides version functionality.
package version

// Version is the server version, set at build time via ldflags.
var Version = "dev"

// AgentVersion is the latest agent release version, set at build time via ldflags.
// Sourced from .agent-version file. Used as default for latest_agent_version.
var AgentVersion = "dev"

// Commit is the git commit hash, set at build time via ldflags.
var Commit = "unknown"

// BuiltAt is the build timestamp, set at build time via ldflags.
var BuiltAt string
