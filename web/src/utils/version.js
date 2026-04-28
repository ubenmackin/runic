// Compare agent versions using semantic versioning.
// Returns true only when peerVersion is strictly less than latestVersion.
export function isAgentOutdated(peerVersion, latestVersion) {
  if (!peerVersion || !latestVersion) return false
  const stripV = (v) => v.replace(/^v/, '')
  const parse = (v) => stripV(v).split('.').map(Number)
  const peer = parse(peerVersion)
  const latest = parse(latestVersion)
  for (let i = 0; i < Math.max(peer.length, latest.length); i++) {
    const p = peer[i] || 0
    const l = latest[i] || 0
    if (p < l) return true
    if (p > l) return false
  }
  return false // equal versions
}
