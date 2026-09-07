// Package arch is the single shared source for agent binary architecture
// sets consumed by the agent updater, the /downloads freshness check, and
// peer arch validation.
//
// UpdateArchs is canonical: every GOARCH the agent updater can request, every
// filename the staged-dir freshness check requires, and every arch a peer
// must report to be eligible for an update notification. ValidPeerArchs is
// the wider set accepted for peer records (it admits legacy armv6 and the
// free-form other bucket for inventory); only UpdateArchs is servable for
// self-update. The armv6 binary remains servable for legacy manual
// downloads but is excluded from the required set because GOARCH never
// reports armv6, so requiring it only produces spurious failed_validation.
package arch

// UpdateArchs lists the GOARCH values the agent updater can request and the
// server must stage. Canonical source for FilenameForArch,
// RequiredAgentBinaries, and update eligibility.
var UpdateArchs = []string{"amd64", "arm64", "arm"}

// ValidPeerArchs lists the arch values accepted for peer records. It is a
// superset of UpdateArchs: armv6 persists for legacy inventory and other is
// the free-form bucket. Peers reporting armv6 or other are stored but can
// never self-update (no updater mapping, no servable binary for other).
var ValidPeerArchs = []string{"amd64", "arm64", "arm", "armv6", "other"}

// ServiceFilename is the non-arch systemd unit servable under /downloads.
const ServiceFilename = "runic-agent.service"

// LegacyARMv6Filename remains servable for legacy manual downloads but is
// excluded from RequiredAgentBinaries because the updater never requests it.
const LegacyARMv6Filename = "runic-agent-armv6"

// FilenameForArch maps a runtime GOARCH to the whitelisted download filename
// served under /downloads. It reports false for any arch outside UpdateArchs
// (including armv6, other, and empty).
func FilenameForArch(arch string) (string, bool) {
	if IsUpdateSupportedArch(arch) {
		return "runic-agent-" + arch, true
	}
	return "", false
}

// IsUpdateSupportedArch reports whether arch can self-update, i.e. the
// updater has a filename mapping and the server stages a binary for it.
func IsUpdateSupportedArch(arch string) bool {
	for _, a := range UpdateArchs {
		if a == arch {
			return true
		}
	}
	return false
}

// IsValidPeerArch reports whether arch is admissible for peer records.
// Callers allow empty separately (unset arch on legacy peers); empty itself
// is not in the list.
func IsValidPeerArch(arch string) bool {
	for _, a := range ValidPeerArchs {
		if a == arch {
			return true
		}
	}
	return false
}

// RequiredAgentBinaries returns the per-arch agent binaries a server deploy
// must stage before a fan-out may honestly report sent. Derived from
// UpdateArchs so the freshness check can never drift from the updater.
func RequiredAgentBinaries() []string {
	out := make([]string, 0, len(UpdateArchs))
	for _, a := range UpdateArchs {
		if f, ok := FilenameForArch(a); ok {
			out = append(out, f)
		}
	}
	return out
}

// IsServableFile reports whether filename is whitelisted under /downloads:
// every required per-arch binary, the legacy armv6 binary, and the systemd
// unit. Anything else is rejected with 404.
func IsServableFile(filename string) bool {
	if filename == ServiceFilename || filename == LegacyARMv6Filename {
		return true
	}
	for _, a := range UpdateArchs {
		if f, ok := FilenameForArch(a); ok && f == filename {
			return true
		}
	}
	return false
}
