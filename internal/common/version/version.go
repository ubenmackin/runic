// Package version is the single source of truth for build version information.
//
// Version is the server version injected at build time from `git describe`.
// AgentVersion is the agent version injected at build time from the
// .agent-version file and served as latest_agent_version via /api/v1/info.
// Commit and BuiltAt are injected from git and date for both binaries.
// Without ldflags injection (e.g. `go run`), values fall back to dev/unknown/empty.
package version

import (
	"fmt"
	"os"
)

var Version = "dev"

// AgentVersion is the agent version sourced from the .agent-version file
// at build time via AGENT_LD_FLAGS. It backs `runic-agent -version`,
// the agent startup log, heartbeat/register payloads, and the server's
// latest_agent_version in /api/v1/info.
var AgentVersion = "dev"

var Commit = "unknown"

var BuiltAt string

// PrintVersion prints the version information for the named binary and then
// terminates the process with os.Exit(0). It is intended to be wired to a
// `-version` CLI flag and never returns.
func PrintVersion(name, ver string) {
	fmt.Printf("%s version %s (commit %s, built %s)\n", name, ver, Commit, BuiltAt)
	os.Exit(0)
}
