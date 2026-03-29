package version

import (
	"time"
)

// Version is the server version, set at build time via ldflags.
var Version = "dev"

// Commit is the git commit hash, set at build time via ldflags.
var Commit = "unknown"

// BuiltAt is the build timestamp, set at build time via ldflags.
var BuiltAt string

// BuiltAtTime parses the BuiltAt string into a time.Time.
func BuiltAtTime() time.Time {
	t, _ := time.Parse(time.RFC3339, BuiltAt)
	return t
}
