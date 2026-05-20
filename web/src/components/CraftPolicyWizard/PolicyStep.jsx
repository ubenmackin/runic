import { useState } from "react";
import InlineError from "../InlineError";
import SearchableSelect from "../SearchableSelect";
import ToggleSwitch from "../ToggleSwitch";
import { parseCompositePeerValue } from "../../utils/peerUtils";

// Policy Configuration Step Component
export default function PolicyStep({
  policyConfig,
  setPolicyConfig,
  service,
  direction,
  formErrors,
  // Editable field props
  peerOptions = [],
  serviceOptions = [],
  selectedSourcePeerId,
  selectedTargetPeerId,
  selectedServiceId,
  selectedDirection,
  setSelectedSourcePeerId,
  setSelectedTargetPeerId,
  setSelectedServiceId,
  setSelectedDirection,
  editMode = { source: false, target: false, service: false, direction: false },
  toggleEditMode,
  peersLoading = false,
  getSourceDisplay = () => null,
  getTargetDisplay = () => null,
  allPeers = [],
}) {
  const [showDescription, setShowDescription] = useState(false);

  // Handle target_scope with default 'both'
  const targetScope = policyConfig.target_scope || "both";

  // Determine the effective direction for display
  const effectiveDirection = selectedDirection || direction;

  // Helper to get the actual peer object from a selected peer ID (handles composite values)
  const getPeerFromSelection = (selectedId) => {
    if (!selectedId) return null;
    // Handle composite values like "peer:5:10.20.10.20"
    const composite = parseCompositePeerValue(selectedId);
    if (composite) {
      return allPeers.find((p) => p.id === composite.id) || null;
    }
    // Handle special pending values
    if (selectedId === "pending-source" || selectedId === "pending-target") {
      return null;
    }
    // Regular peer ID
    return allPeers.find((p) => p.id === selectedId) || null;
  };

  // Helper to detect if a selected value is a group
  const isGroupSelection = (selectedId) => {
    return typeof selectedId === 'string' && selectedId.startsWith('group:');
  };

  // Extract source/target type from selection
  const sourceType = isGroupSelection(selectedSourcePeerId) ? 'group' : 'peer';
  const targetType = isGroupSelection(selectedTargetPeerId) ? 'group' : 'peer';

  // Compute whether the forward button should be enabled (handles null peer case)
  // Forward pushes FROM Source: enabled if source is Agent peer (not manual) OR Group
  // If sourcePeer is null/undefined, treat as non-manual (enable button)
  const sourcePeer = getPeerFromSelection(selectedSourcePeerId);
  const _canEnableForward = selectedSourcePeerId && (
    (sourceType === 'peer' && (!sourcePeer || !sourcePeer.is_manual)) ||
    sourceType === 'group'
  );

  // Compute whether the backward button should be enabled (handles null peer case)
  // Backward pushes TO Target: enabled if target is Agent peer (not manual) OR Group
  // If targetPeer is null/undefined, treat as non-manual (enable button)
  const targetPeer = getPeerFromSelection(selectedTargetPeerId);
  const _canEnableBackward = selectedTargetPeerId && (
    (targetType === 'peer' && (!targetPeer || !targetPeer.is_manual)) ||
    targetType === 'group'
  );

  return (
    <div className="space-y-4">
      {/* Row 1: Name and Priority */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label
            htmlFor="policy-name"
            className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1"
          >
            Name <span className="text-red-500">*</span>
          </label>
          <input
            id="policy-name"
            type="text"
            value={policyConfig.name}
            onChange={(e) =>
              setPolicyConfig((prev) => ({ ...prev, name: e.target.value }))
            }
            placeholder="Enter policy name"
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
          />
          {formErrors.name && <InlineError message={formErrors.name} />}
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
            Priority
          </label>
          <input
            type="number"
            value={policyConfig.priority}
            onChange={(e) =>
              setPolicyConfig((prev) => ({
                ...prev,
                priority: parseInt(e.target.value) || 100,
              }))
            }
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
          />
        </div>
      </div>

      {/* Row 2: Description - collapsible */}
      <div className="border border-gray-200 dark:border-gray-border rounded-none overflow-hidden">
        <button
          type="button"
          onClick={() => setShowDescription(!showDescription)}
          className="w-full px-4 py-3 flex items-center justify-between bg-gray-50 dark:bg-charcoal-darkest hover:bg-gray-100 dark:hover:bg-charcoal-dark transition-colors"
        >
          <span className="text-sm font-medium text-gray-700 dark:text-amber-primary">
            Description (Optional)
          </span>
          <svg
            className={`w-4 h-4 text-gray-500 transition-transform duration-150 ${showDescription ? "rotate-180" : ""}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M19 9l-7 7-7-7"
            />
          </svg>
        </button>
        <div
          className={`transition-all duration-150 ease-in-out ${showDescription ? "max-h-32 opacity-100" : "max-h-0 opacity-0"} overflow-hidden`}
        >
          <div className="p-4">
            <textarea
              value={policyConfig.description}
              onChange={(e) =>
                setPolicyConfig((prev) => ({
                  ...prev,
                  description: e.target.value,
                }))
              }
              rows={2}
              placeholder="Add a description for this policy..."
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
            />
          </div>
        </div>
      </div>

{/* Row 3 & 4: Source [Direction Arrows] Target / Service [spacer] Action - using CSS Grid */}
<div className="grid grid-cols-1 sm:grid-cols-[1fr_auto_1fr] gap-x-4 gap-y-4 items-end">
        {/* Source Column */}
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
            Source
          </label>
          {editMode.source ? (
            <SearchableSelect
              options={peerOptions}
              value={selectedSourcePeerId}
              onChange={(val) => {
                setSelectedSourcePeerId(val);
                toggleEditMode("source");
              }}
              placeholder="Select source peer..."
              disabled={peersLoading}
            />
          ) : (
            <div className="flex items-center justify-between p-2 border border-gray-200 dark:border-gray-border rounded-none bg-gray-50 dark:bg-charcoal-darkest">
              <span
                className="font-medium text-gray-900 dark:text-light-neutral text-sm truncate"
                title={
                  getSourceDisplay()
                }
              >
                {getSourceDisplay()}
              </span>
              <button
                type="button"
                onClick={() => toggleEditMode("source")}
                className="text-xs text-purple-active hover:underline ml-2"
              >
                Edit
              </button>
            </div>
          )}
        </div>

        {/* Direction Column - Green Arrow Buttons */}
        <div className="flex flex-col items-center justify-end gap-1.5 pb-0.5">
          <div className="flex flex-col gap-1.5">
            {/* Forward button */}
            <button
              type="button"
              onClick={() => {
                if (
                  effectiveDirection === "forward" ||
                  effectiveDirection === "OUT"
                )
                  return;
                setSelectedDirection((d) =>
                  d === "both"
                    ? "backward"
                    : d === "backward"
                      ? "both"
                      : "forward",
                );
              }}
              disabled={
                effectiveDirection === "forward" || effectiveDirection === "OUT"
              }
              className={`flex items-center justify-center w-28 h-8 rounded-none border-2 transition-all duration-200 ${
                effectiveDirection === "both" ||
                effectiveDirection === "forward" ||
                effectiveDirection === "OUT"
                  ? "bg-emerald-900/80 border-emerald-500 text-emerald-400 hover:bg-emerald-800/80"
                  : "bg-gray-200 dark:bg-gray-800 border-gray-300 dark:border-gray-600 text-gray-400 dark:text-gray-500 hover:bg-gray-300 dark:hover:bg-gray-700"
              }`}
              title="Forward: Source → Target"
            >
              <svg
                viewBox="0 0 80 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="w-16 h-4"
              >
                <line x1="8" y1="12" x2="66" y2="12" />
                <polyline points="58,6 66,12 58,18" />
              </svg>
            </button>
            {/* Backward button */}
            <button
              type="button"
              onClick={() => {
                if (
                  effectiveDirection === "backward" ||
                  effectiveDirection === "IN"
                )
                  return;
                setSelectedDirection((d) =>
                  d === "both"
                    ? "forward"
                    : d === "forward"
                      ? "both"
                      : "backward",
                );
              }}
              disabled={
                effectiveDirection === "backward" || effectiveDirection === "IN"
              }
              className={`flex items-center justify-center w-28 h-8 rounded-none border-2 transition-all duration-200 ${
                effectiveDirection === "both" ||
                effectiveDirection === "backward" ||
                effectiveDirection === "IN"
                  ? "bg-blue-900/80 border-blue-500 text-blue-400 hover:bg-blue-800/80"
                  : "bg-gray-200 dark:bg-gray-800 border-gray-300 dark:border-gray-600 text-gray-400 dark:text-gray-500 hover:bg-gray-300 dark:hover:bg-gray-700"
              }`}
              title="Backward: Target → Source"
            >
              <svg
                viewBox="0 0 80 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="w-16 h-4"
              >
                <line x1="72" y1="12" x2="14" y2="12" />
                <polyline points="22,6 14,12 22,18" />
              </svg>
            </button>
          </div>
        </div>

        {/* Target Column */}
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
            Target
          </label>
          {editMode.target ? (
            <SearchableSelect
              options={peerOptions}
              value={selectedTargetPeerId}
              onChange={(val) => {
                setSelectedTargetPeerId(val);
                toggleEditMode("target");
              }}
              placeholder="Select target peer..."
              disabled={peersLoading}
            />
          ) : (
            <div className="flex items-center justify-between p-2 border border-gray-200 dark:border-gray-border rounded-none bg-gray-50 dark:bg-charcoal-darkest">
              <span
                className="font-medium text-gray-900 dark:text-light-neutral text-sm truncate"
          title={getTargetDisplay()}
        >
          {getTargetDisplay()}
              </span>
              <button
                type="button"
                onClick={() => toggleEditMode("target")}
                className="text-xs text-purple-active hover:underline ml-2"
              >
                Edit
              </button>
            </div>
)}
</div>

{/* Service Column */}
<div>
          <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
            Service
          </label>
          {editMode.service ? (
            <SearchableSelect
              options={serviceOptions}
              value={selectedServiceId}
              onChange={(val) => {
                setSelectedServiceId(val);
                toggleEditMode("service");
              }}
              placeholder="Select service..."
              disabled={peersLoading}
            />
          ) : (
            <div className="flex items-center justify-between p-2 border border-gray-200 dark:border-gray-border rounded-none bg-gray-50 dark:bg-charcoal-darkest">
              <span
                className="font-medium text-gray-900 dark:text-light-neutral text-sm truncate"
                title={service?.name}
              >
                {service?.name || "Unknown"}
              </span>
              <button
                type="button"
                onClick={() => toggleEditMode("service")}
                className="text-xs text-purple-active hover:underline ml-2"
              >
                Edit
              </button>
            </div>
          )}
        </div>

{/* Spacer */}
<div>{/* spacer */}</div>

{/* Action Column - ACCEPT badge */}
<div>
          <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
            Action
          </label>
          <span className="inline-block px-2 py-1 text-xs font-medium bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300 rounded-none">
            ACCEPT
          </span>
        </div>
      </div>

      {/* Row 5: Applies To - 3-button selection */}
      <div>
        <div className="flex items-center gap-2 mb-2">
          <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary">
            Applies To
          </label>
          <span className="text-xs text-gray-500 dark:text-amber-muted">
            (Docker Integration)
          </span>
        </div>
        <div className="flex bg-gray-100 dark:bg-charcoal-darkest p-1 rounded-none border border-gray-200 dark:border-gray-border">
          <button
            type="button"
            onClick={() =>
              setPolicyConfig((d) => ({ ...d, target_scope: "both" }))
            }
            className={`flex-1 py-1.5 text-xs font-medium rounded-none transition-all duration-200 ${
              targetScope === "both" || !targetScope
                ? "bg-white dark:bg-charcoal-dark text-gray-900 dark:text-white ring-1 ring-black/5 dark:ring-white/10"
                : "text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-white/50 dark:hover:bg-charcoal-dark/50"
            }`}
          >
            Host + Docker
          </button>
          <button
            type="button"
            onClick={() =>
              setPolicyConfig((d) => ({ ...d, target_scope: "host" }))
            }
            className={`flex-1 py-1.5 text-xs font-medium rounded-none transition-all duration-200 ${
              targetScope === "host"
                ? "bg-white dark:bg-charcoal-dark text-gray-900 dark:text-white ring-1 ring-black/5 dark:ring-white/10"
                : "text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-white/50 dark:hover:bg-charcoal-dark/50"
            }`}
          >
            Host Only
          </button>
          <button
            type="button"
            onClick={() =>
              setPolicyConfig((d) => ({ ...d, target_scope: "docker" }))
            }
            className={`flex-1 py-1.5 text-xs font-medium rounded-none transition-all duration-200 ${
              targetScope === "docker"
                ? "bg-white dark:bg-charcoal-dark text-gray-900 dark:text-white ring-1 ring-black/5 dark:ring-white/10"
                : "text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-white/50 dark:hover:bg-charcoal-dark/50"
            }`}
          >
            Docker Only
          </button>
        </div>
      </div>

      {/* Row 6: Policy Enabled - in its own well */}
      <div className="flex items-center justify-between p-4 bg-gray-50 dark:bg-charcoal-darkest border border-gray-200 dark:border-gray-border rounded-none">
        <div>
          <label className="text-sm font-medium text-gray-900 dark:text-light-neutral">
            Policy Enabled
          </label>
          <p className="text-xs text-gray-500 dark:text-amber-muted">
            When disabled, this policy will not generate any firewall rules
            until re-enabled.
          </p>
        </div>
        <ToggleSwitch
          checked={policyConfig.enabled}
          onChange={(v) => setPolicyConfig((prev) => ({ ...prev, enabled: v }))}
        />
      </div>

      <InlineError message={formErrors._general} />
    </div>
  );
}
