import { parseCompositePeerValue } from "../../utils/peerUtils";

// Helper function to render ports as boxed/chip items
// Handles: single port (80), multiple ports (80,443), ranges (8000:9000)
export function renderPortsAsChips(portsString) {
  if (!portsString) return <span className="text-gray-400">—</span>;

  // Split by comma to handle multiple ports/ranges
  const portItems = portsString.split(",");

  return (
    <span className="flex flex-wrap gap-1">
      {portItems.map((item, idx) => (
        <span
          key={idx}
          className="px-2 py-0.5 bg-gray-200 dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral rounded text-xs font-mono"
        >
          {item.trim()}
        </span>
      ))}
    </span>
  );
}

// Shared utility to resolve a peer display name from a selected peer ID or fallback peer.
// Handles the "pending-source" and "pending-target" sentinel values and returns the fallback string when no
// peer information is available. Callers can customise the fallback (e.g. "—" for
// review displays, "Unknown" for editable-field displays). Renamed from getSourceDisplayValue
// to reflect that it handles both source and target peers.
export function getPeerDisplayValue({
  selectedPeerId,
  allPeers = [],
  fallbackPeer,
  fallback = "Unknown",
}) {
  // Check for composite value first (e.g., "peer:5:10.20.10.20")
  const composite = parseCompositePeerValue(selectedPeerId);
  if (composite) {
    const peer = allPeers.find((p) => p.id === composite.id);
    const hostname = peer?.hostname || peer?.ip_address || fallback;
    return composite.ip ? `${hostname} (${composite.ip})` : hostname;
  }
  if (selectedPeerId) {
    if (selectedPeerId === "pending-source" || selectedPeerId === "pending-target") {
      return fallbackPeer?.hostname || fallbackPeer?.ip_address || fallback;
    }
    const peer = allPeers.find((p) => p.id === selectedPeerId);
    return peer?.hostname || peer?.ip_address || fallback;
  }
  return fallbackPeer?.hostname || fallbackPeer?.ip_address || fallback;
}
