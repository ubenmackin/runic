import { Loader2, AlertCircle, Check } from "lucide-react";
import InlineError from "../InlineError";
import SearchableSelect from "../SearchableSelect";
import { renderPortsAsChips } from "./shared";

// Service Step Component
export default function ServiceStep({
  port,
  protocol,
  existingService,
  newService,
  setNewService,
  serviceLoading,
  serviceError,
  formErrors,
  protocolOptions,
}) {
  const handleNewServiceChange = (field, value) => {
    setNewService((prev) => ({ ...prev, [field]: value }));
  };

  if (serviceLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-8 space-y-3">
        <Loader2 className="w-6 h-6 text-purple-active animate-spin" />
        <p className="text-sm text-gray-500 dark:text-amber-muted">
          Looking up service by port...
        </p>
      </div>
    );
  }

  if (serviceError && !existingService) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2 p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-none">
          <AlertCircle className="w-4 h-4 text-amber-600 dark:text-amber-400" />
          <p className="text-sm text-amber-700 dark:text-amber-300">
No existing service found for{" "}
              <span className="font-mono font-medium">
                {port ? `${port}/${protocol}` : protocol}
              </span>
          </p>
        </div>
        <p className="text-sm text-gray-600 dark:text-amber-muted">
          Create a new service for this port.
        </p>

        {/* New Service Form */}
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
              Name <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={newService.name}
              onChange={(e) => handleNewServiceChange("name", e.target.value)}
              placeholder="e.g., Web Server, Database"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
            />
            {formErrors.name && <InlineError message={formErrors.name} />}
          </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
            Protocol
          </label>
          <SearchableSelect
            options={protocolOptions}
            value={newService.protocol}
            onChange={(v) => handleNewServiceChange("protocol", v)}
            placeholder="Select protocol..."
            disabled={newService.protocol === "icmp" || newService.protocol === "igmp"}
          />
        </div>

        {newService.protocol !== "icmp" && newService.protocol !== "igmp" && (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
              Destination Ports <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={newService.ports}
              onChange={(e) => handleNewServiceChange("ports", e.target.value)}
              placeholder="e.g., 443 or 80,443 or 8000:9000"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
            />
            <p className="text-xs text-gray-500 dark:text-amber-muted mt-1">
              Single port, comma-separated, or range (e.g., 443, 80,443, or
              8000:9000)
            </p>
            {formErrors.ports && <InlineError message={formErrors.ports} />}
          </div>
        )}
        </div>

        <InlineError message={formErrors._general} />
      </div>
    );
  }

  if (existingService) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-none">
          <Check className="w-4 h-4 text-green-600 dark:text-green-400" />
          <p className="text-sm text-green-700 dark:text-green-300">
            Found existing service:{" "}
            <span className="font-medium">{existingService.name}</span>
          </p>
        </div>
        {/* Display service details inline */}
        <div className="text-sm">
          <div className="mb-1">
            <span className="text-gray-500 dark:text-amber-muted">
              Protocol:
            </span>{" "}
            <span className="text-gray-900 dark:text-light-neutral uppercase">
              {existingService.protocol}
            </span>
          </div>
          <div>
            <span className="text-gray-500 dark:text-amber-muted">Ports:</span>{" "}
            {renderPortsAsChips(existingService.ports)}
          </div>
        </div>
        <p className="text-xs text-gray-500 dark:text-amber-muted">
          This service is already defined and will be used for the policy.
        </p>
      </div>
    );
  }

  return null;
}
