import { Server, Package, Shield } from "lucide-react";
import { renderPortsAsChips, getPeerDisplayValue } from "./shared";

// Review Step Component
export default function ReviewStep({
  existingPeer,
  newPeer,
  createNewPeerMode,
  existingService,
  newService,
  policyConfig,
  sourcePeer,
  targetPeer,
  direction,
  // Override values
  selectedSourcePeerId,
  selectedTargetPeerId,
  selectedServiceId,
  selectedDirection,
  allPeers = [],
  allServices = [],
}) {
  const peerToShow = createNewPeerMode ? newPeer : existingPeer || newPeer;
  const serviceToShow = existingService || newService;

  // Get display values considering user overrides
  const getSourceDisplay = () =>
    getPeerDisplayValue({
      selectedPeerId: selectedSourcePeerId,
      allPeers,
      fallbackPeer: sourcePeer,
      fallback: "—",
    });

  const getTargetDisplay = () =>
    getPeerDisplayValue({
      selectedPeerId: selectedTargetPeerId,
      allPeers,
      fallbackPeer: targetPeer,
      fallback: "—",
    });

  const getServiceDisplay = () => {
    if (selectedServiceId) {
      const svc = allServices.find((s) => s.id === selectedServiceId);
      return svc?.name || "—";
    }
    return serviceToShow?.name || "—";
  };

  const getDirectionDisplay = () => {
    const effectiveDirection = selectedDirection || direction;
    if (effectiveDirection === "forward" || effectiveDirection === "OUT")
      return "Forward";
    if (effectiveDirection === "backward" || effectiveDirection === "IN")
      return "Backward";
    if (effectiveDirection === "both") return "Both";
    return "Forward"; // Default fallback
  };

  return (
    <div className="space-y-4">
      {/* PEER Section */}
      <div className="border border-gray-200 dark:border-gray-border rounded-none overflow-hidden">
        <div className="px-4 py-2 bg-gray-50 dark:bg-charcoal-darkest border-b border-gray-200 dark:border-gray-border">
          <h4 className="text-sm font-medium text-gray-900 dark:text-light-neutral flex items-center gap-2">
            <Server className="w-4 h-4" />
            PEER {createNewPeerMode || !existingPeer ? "(New)" : "(Existing)"}
          </h4>
        </div>
        <div className="p-4 space-y-2 text-sm">
          <div className="grid grid-cols-2 gap-4">
            <div>
<span className="text-gray-500 dark:text-amber-muted">
              Name:
            </span>
            <span className="ml-2 font-medium text-gray-900 dark:text-light-neutral">
              {peerToShow?.hostname || "—"}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">
                IP Address:
              </span>
              <span className="ml-2 font-mono text-gray-900 dark:text-light-neutral">
                {peerToShow?.ip_address || "—"}
              </span>
            </div>
            {peerToShow?.os_type && (
              <div>
                <span className="text-gray-500 dark:text-amber-muted">OS:</span>
                <span className="ml-2 text-gray-900 dark:text-light-neutral">
                  {peerToShow.os_type}
                </span>
              </div>
            )}
            {peerToShow?.arch && (
              <div>
                <span className="text-gray-500 dark:text-amber-muted">
                  Architecture:
                </span>
                <span className="ml-2 text-gray-900 dark:text-light-neutral">
                  {peerToShow.arch}
                </span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* SERVICE Section */}
      <div className="border border-gray-200 dark:border-gray-border rounded-none overflow-hidden">
        <div className="px-4 py-2 bg-gray-50 dark:bg-charcoal-darkest border-b border-gray-200 dark:border-gray-border">
          <h4 className="text-sm font-medium text-gray-900 dark:text-light-neutral flex items-center gap-2">
            <Package className="w-4 h-4" />
            SERVICE {existingService ? "(Existing)" : "(New)"}
          </h4>
        </div>
        <div className="p-4 space-y-2 text-sm">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="text-gray-500 dark:text-amber-muted">Name:</span>
              <span className="ml-2 font-medium text-gray-900 dark:text-light-neutral">
                {serviceToShow?.name || "—"}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">
                Protocol:
              </span>
              <span className="ml-2 text-gray-900 dark:text-light-neutral uppercase">
                {serviceToShow?.protocol || "—"}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">
                Ports:
              </span>
              <span className="ml-2">
                {renderPortsAsChips(serviceToShow?.ports)}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* POLICY Section */}
      <div className="border border-gray-200 dark:border-gray-border rounded-none overflow-hidden">
        <div className="px-4 py-2 bg-gray-50 dark:bg-charcoal-darkest border-b border-gray-200 dark:border-gray-border">
          <h4 className="text-sm font-medium text-gray-900 dark:text-light-neutral flex items-center gap-2">
            <Shield className="w-4 h-4" />
            POLICY
          </h4>
        </div>
        <div className="p-4 space-y-2 text-sm">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="text-gray-500 dark:text-amber-muted">Name:</span>
              <span className="ml-2 font-medium text-gray-900 dark:text-light-neutral">
                {policyConfig?.name || "—"}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">
                Priority:
              </span>
              <span className="ml-2 font-mono text-gray-900 dark:text-light-neutral">
                {policyConfig?.priority}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">
                Source:
              </span>
              <span className="ml-2 text-gray-900 dark:text-light-neutral">
                {getSourceDisplay()}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">
                Target:
              </span>
              <span className="ml-2 text-gray-900 dark:text-light-neutral">
                {getTargetDisplay()}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">
                Service:
              </span>
              <span className="ml-2 text-gray-900 dark:text-light-neutral">
                {getServiceDisplay()}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">
                Action:
              </span>
              <span className="ml-2 px-2 py-0.5 text-xs font-medium bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300 rounded-none">
                ACCEPT
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">
                Target Scope:
              </span>
              <span className="ml-2 text-gray-900 dark:text-light-neutral">
                {policyConfig?.target_scope === "host"
                  ? "Host Only"
                  : policyConfig?.target_scope === "docker"
                    ? "Docker Only"
                    : "Host + Docker"}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">
                Direction:
              </span>
              <span className="ml-2 text-gray-900 dark:text-light-neutral">
                {getDirectionDisplay()}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">
                Enabled:
              </span>
              <span
                className={`ml-2 ${policyConfig?.enabled ? "text-green-600 dark:text-green-400" : "text-red-600 dark:text-red-400"}`}
              >
                {policyConfig?.enabled ? "Yes" : "No"}
              </span>
            </div>
          </div>
          {policyConfig?.description && (
            <div className="mt-2 pt-2 border-t border-gray-200 dark:border-gray-border">
              <span className="text-gray-500 dark:text-amber-muted">
                Description:
              </span>
              <p className="mt-1 text-gray-900 dark:text-light-neutral">
                {policyConfig.description}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
