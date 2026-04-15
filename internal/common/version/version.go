// Package version provides version functionality.
package version

// Version is the server version, set at build time via ldflags.
var Version = "dev"

// Commit is the git commit hash, set at build time via ldflags.
var Commit = "unknown"

// BuiltAt is the build timestamp, set at build time via ldflags.
var BuiltAt string
