package identity

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDetectOSReadsFromOSReleasePath tests that DetectOS reads from the
// configurable osReleasePath variable, allowing unit tests to supply a
// temporary os-release file.
func TestDetectOSReadsFromOSReleasePath(t *testing.T) {
	// Create a temp file that looks like /etc/os-release
	dir := t.TempDir()
	osReleaseFile := filepath.Join(dir, "os-release")

	content := `NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_ID="22.04"
`
	if err := os.WriteFile(osReleaseFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp os-release: %v", err)
	}

	// Override the package-level path and restore it after the test
	orig := osReleasePath
	osReleasePath = osReleaseFile
	defer func() { osReleasePath = orig }()

	id, err := DetectOS()
	if err != nil {
		t.Fatalf("DetectOS() returned error: %v", err)
	}
	if id != "ubuntu" {
		t.Errorf("DetectOS() = %q, want %q", id, "ubuntu")
	}
}

// TestDetectOSWithQuotedID tests that DetectOS correctly strips quotes from ID values.
func TestDetectOSWithQuotedID(t *testing.T) {
	dir := t.TempDir()
	osReleaseFile := filepath.Join(dir, "os-release")

	content := `NAME="openSUSE Leap"
VERSION="15.5"
ID="opensuse-leap"
`
	if err := os.WriteFile(osReleaseFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp os-release: %v", err)
	}

	orig := osReleasePath
	osReleasePath = osReleaseFile
	defer func() { osReleasePath = orig }()

	id, err := DetectOS()
	if err != nil {
		t.Fatalf("DetectOS() returned error: %v", err)
	}
	if id != "opensuse-leap" {
		t.Errorf("DetectOS() = %q, want %q", id, "opensuse-leap")
	}
}

// TestDetectOSReturnsErrorOnMissingFile tests that DetectOS returns an error
// when the os-release file does not exist.
func TestDetectOSReturnsErrorOnMissingFile(t *testing.T) {
	orig := osReleasePath
	osReleasePath = "/nonexistent/path/os-release"
	defer func() { osReleasePath = orig }()

	_, err := DetectOS()
	if err == nil {
		t.Error("DetectOS() expected error for missing file, got nil")
	}
}

// TestDetectOSReturnsErrorWhenIDMissing tests that DetectOS returns an error
// when the os-release file exists but contains no ID= line.
func TestDetectOSReturnsErrorWhenIDMissing(t *testing.T) {
	dir := t.TempDir()
	osReleaseFile := filepath.Join(dir, "os-release")

	content := `NAME="SomeOS"
VERSION="1.0"
PRETTY_NAME="SomeOS 1.0"
`
	if err := os.WriteFile(osReleaseFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp os-release: %v", err)
	}

	orig := osReleasePath
	osReleasePath = osReleaseFile
	defer func() { osReleasePath = orig }()

	_, err := DetectOS()
	if err == nil {
		t.Error("DetectOS() expected error when ID= line is missing, got nil")
	}
}

// TestDetectOSWithDebianID tests that DetectOS returns "debian" for a Debian os-release.
func TestDetectOSWithDebianID(t *testing.T) {
	dir := t.TempDir()
	osReleaseFile := filepath.Join(dir, "os-release")

	content := `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
ID=debian
`
	if err := os.WriteFile(osReleaseFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp os-release: %v", err)
	}

	orig := osReleasePath
	osReleasePath = osReleaseFile
	defer func() { osReleasePath = orig }()

	id, err := DetectOS()
	if err != nil {
		t.Fatalf("DetectOS() returned error: %v", err)
	}
	if id != "debian" {
		t.Errorf("DetectOS() = %q, want %q", id, "debian")
	}
}

// TestDetectOSWithArmbianID tests that DetectOS returns "debian" for Armbian
// systems where /etc/os-release has ID=debian (the common case on real Armbian).
func TestDetectOSWithArmbianID(t *testing.T) {
	dir := t.TempDir()
	osReleaseFile := filepath.Join(dir, "os-release")

	// Real Armbian systems have ID=debian with ARMBIAN_PRETTY_NAME set
	content := `PRETTY_NAME="Armbian 23.8.1 bookworm"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
ID=debian
ARMBIAN_PRETTY_NAME="Armbian 23.8.1 bookworm"
`
	if err := os.WriteFile(osReleaseFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp os-release: %v", err)
	}

	orig := osReleasePath
	osReleasePath = osReleaseFile
	defer func() { osReleasePath = orig }()

	id, err := DetectOS()
	if err != nil {
		t.Fatalf("DetectOS() returned error: %v", err)
	}
	// Armbian has ID=debian, so DetectOS returns "debian"
	if id != "debian" {
		t.Errorf("DetectOS() = %q, want %q", id, "debian")
	}
}

// TestNormalizeOSMapsArmbianToDebian tests that NormalizeOS maps "armbian" to "debian".
func TestNormalizeOSMapsArmbianToDebian(t *testing.T) {
	result := NormalizeOS("armbian")
	if result != "debian" {
		t.Errorf("NormalizeOS(%q) = %q, want %q", "armbian", result, "debian")
	}
}

// TestNormalizeOSMapsKnownIDsCorrectly tests that NormalizeOS maps known IDs correctly.
func TestNormalizeOSMapsKnownIDsCorrectly(t *testing.T) {
	testCases := []struct {
		id       string
		expected string
	}{
		{"ubuntu", "ubuntu"},
		{"debian", "debian"},
		{"armbian", "debian"},
		{"fedora", "rhel"},
		{"rhel", "rhel"},
		{"centos", "rhel"},
		{"opensuse", "opensuse"},
		{"opensuse-leap", "opensuse"},
		{"opensuse-tumbleweed", "opensuse"},
		{"raspbian", "raspbian"},
		{"arch", "arch"},
		{"archarm", "arch"},
		{"manjaro", "arch"},
		{"endeavouros", "arch"},
		{"rocky", "rhel"},
		{"almalinux", "rhel"},
		{"ol", "rhel"},
		{"suse", "opensuse"},
		{"sled", "opensuse"},
		{"sles", "opensuse"},
		{"linuxmint", "ubuntu"},
		{"pop", "ubuntu"},
	}

	for _, tc := range testCases {
		t.Run(tc.id, func(t *testing.T) {
			result := NormalizeOS(tc.id)
			if result != tc.expected {
				t.Errorf("NormalizeOS(%q) = %q, want %q", tc.id, result, tc.expected)
			}
		})
	}
}
