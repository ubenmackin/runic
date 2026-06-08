// Package version provides version functionality.
package version

import (
	"fmt"
	"os"
)

var Version = "dev"

// AgentVersion is sourced from .agent-version file. Used as default for latest_agent_version.
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
