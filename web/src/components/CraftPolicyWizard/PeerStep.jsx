import { Loader2, AlertCircle, Check } from "lucide-react";
import InlineError from "../InlineError";
import SearchableSelect from "../SearchableSelect";
import { OS_OPTIONS, ARCH_OPTIONS } from "../../constants";

// Peer Step Component
export default function PeerStep({
  externalIP,
  existingPeer,
  newPeer,
  setNewPeer,
  peerLoading,
  peerError,
  createNewPeerMode,
  setCreateNewPeerMode,
  formErrors,
}) {
  const handleNewPeerChange = (field, value) => {
    setNewPeer((prev) => ({ ...prev, [field]: value }));
  };

  if (peerLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-8 space-y-3">
        <Loader2 className="w-6 h-6 text-purple-active animate-spin" />
        <p className="text-sm text-gray-500 dark:text-amber-muted">
          Looking up peer by IP...
        </p>
      </div>
    );
  }

  if (peerError && !createNewPeerMode) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2 p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-none">
          <AlertCircle className="w-4 h-4 text-amber-600 dark:text-amber-400" />
          <p className="text-sm text-amber-700 dark:text-amber-300">
            No existing peer found for IP{" "}
            <span className="font-mono font-medium">{externalIP}</span>
          </p>
        </div>
        <p className="text-sm text-gray-600 dark:text-amber-muted">
          Create a new manual peer entry for this IP address.
        </p>

        {/* New Peer Form */}
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
              Name <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={newPeer.hostname}
              onChange={(e) => handleNewPeerChange("hostname", e.target.value)}
              placeholder="Enter hostname"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
            />
            {formErrors.hostname && (
              <InlineError message={formErrors.hostname} />
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
              IP Address <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={newPeer.ip_address}
              disabled
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-gray-100 dark:bg-charcoal-darkest text-gray-500 dark:text-amber-muted cursor-not-allowed"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                Operating System
              </label>
              <SearchableSelect
                options={OS_OPTIONS}
                value={newPeer.os_type}
                onChange={(v) => handleNewPeerChange("os_type", v)}
                placeholder="Select OS..."
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                Architecture
              </label>
              <SearchableSelect
                options={ARCH_OPTIONS}
                value={newPeer.arch}
                onChange={(v) => handleNewPeerChange("arch", v)}
                placeholder="Select arch..."
              />
            </div>
          </div>
        </div>

        <InlineError message={formErrors._general} />
      </div>
    );
  }

  if (existingPeer && !createNewPeerMode) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-none">
          <Check className="w-4 h-4 text-green-600 dark:text-green-400" />
          <p className="text-sm text-green-700 dark:text-green-300">
            Found existing peer:{" "}
            <span className="font-medium">{existingPeer.hostname}</span> (
            {existingPeer.ip_address})
          </p>
        </div>

        <div className="p-3 bg-gray-50 dark:bg-charcoal-darkest border border-gray-200 dark:border-gray-border rounded-none">
          <div className="grid grid-cols-2 gap-2 text-sm">
            <div>
              <span className="text-gray-500 dark:text-amber-muted">
                        Name:
                      </span>
              <span className="ml-2 font-medium text-gray-900 dark:text-light-neutral">
                {existingPeer.hostname}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">
                IP Address:
              </span>
              <span className="ml-2 font-mono text-gray-900 dark:text-light-neutral">
                {existingPeer.ip_address}
              </span>
            </div>
            {existingPeer.os_type && (
              <div>
                <span className="text-gray-500 dark:text-amber-muted">OS:</span>
                <span className="ml-2 text-gray-900 dark:text-light-neutral">
                  {existingPeer.os_type}
                </span>
              </div>
            )}
          </div>
        </div>

        <button
          type="button"
          onClick={() => setCreateNewPeerMode(true)}
          className="text-sm text-purple-active hover:underline"
        >
          Create a new peer instead
        </button>
      </div>
    );
  }

  // Create new peer mode
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-600 dark:text-amber-muted">
          Creating a new manual peer for IP{" "}
          <span className="font-mono font-medium">{externalIP}</span>
        </p>
        {existingPeer && (
          <button
            type="button"
            onClick={() => setCreateNewPeerMode(false)}
            className="text-sm text-purple-active hover:underline"
          >
            Use existing peer instead
          </button>
        )}
      </div>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
            Name <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            value={newPeer.hostname}
            onChange={(e) => handleNewPeerChange("hostname", e.target.value)}
            placeholder="Enter hostname"
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
          />
          {formErrors.hostname && <InlineError message={formErrors.hostname} />}
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
            IP Address <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            value={newPeer.ip_address}
            disabled
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-gray-100 dark:bg-charcoal-darkest text-gray-500 dark:text-amber-muted cursor-not-allowed"
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
              Operating System
            </label>
            <SearchableSelect
              options={OS_OPTIONS}
              value={newPeer.os_type}
              onChange={(v) => handleNewPeerChange("os_type", v)}
              placeholder="Select OS..."
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
              Architecture
            </label>
            <SearchableSelect
              options={ARCH_OPTIONS}
              value={newPeer.arch}
              onChange={(v) => handleNewPeerChange("arch", v)}
              placeholder="Select arch..."
            />
          </div>
        </div>
      </div>

      <InlineError message={formErrors._general} />
    </div>
  );
}
