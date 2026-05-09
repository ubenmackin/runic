package identity

import (
	"fmt"
	"os"
	"strings"
)

// /etc/os-release but can be overridden in tests to point at a temp file.
var osReleasePath = "/etc/os-release"

// DetectOS detects the OS from /etc/os-release. It returns the raw OS ID (e.g. "ubuntu", "opensuse-leap", "archarm").
// Use NormalizeOS to map variant IDs to canonical family names.
func DetectOS() (string, error) {
	data, err := os.ReadFile(osReleasePath)
	if err != nil {
		return "", fmt.Errorf("read os-release: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ID=") {
			id := strings.TrimPrefix(line, "ID=")
			id = strings.Trim(id, `"`)
			id = strings.ToLower(id)
			return id, nil
		}
	}

	return "", fmt.Errorf("could not detect OS from os-release")
}

// NormalizeOS normalizes the OS ID to a canonical family name. "armbian" maps to "debian" (Armbian's ID is "debian" in os-release).
// If the ID is not recognized, it is returned as-is.
func NormalizeOS(id string) string {
	id = strings.ToLower(id)
	switch {
	case strings.HasPrefix(id, "opensuse"), id == "suse", id == "sled", id == "sles":
		return "opensuse"
	case id == "debian", id == "armbian":
		return "debian"
	case id == "raspbian":
		return "raspbian"
	case id == "ubuntu", id == "pop", id == "linuxmint":
		return "ubuntu"
	case strings.HasPrefix(id, "fedora"), strings.HasPrefix(id, "rhel"), id == "centos",
		id == "rocky", id == "almalinux", id == "ol":
		return "rhel"
	case strings.HasPrefix(id, "arch"), id == "manjaro", id == "endeavouros":
		return "arch"
	default:
		return id
	}
}
