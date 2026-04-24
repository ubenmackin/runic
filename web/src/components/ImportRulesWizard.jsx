import { useState, useEffect, useCallback, useRef } from "react";
import ReactDOM from "react-dom";
import {
  X,
  ChevronLeft,
  ChevronRight,
  Check,
  Loader2,
  Download,
  AlertCircle,
  Eye,
  ArrowRight,
  ArrowLeft,
  MoveHorizontal,
  ChevronDown,
  ChevronUp,
  Server,
  Users,
  Package,
} from "lucide-react";
import { useToastContext } from "../hooks/ToastContext";
import { useFocusTrap } from "../hooks/useFocusTrap";
import { useQueryClient } from "@tanstack/react-query";
import {
  initiateImport,
  getImportSession,
  getImportRules,
  getImportGroups,
  getImportPeers,
  getImportServices,
  getImportSkipped,
  updateImportRule,
  updateImportGroup,
  updateImportPeer,
  updateImportService,
  applyImport,
  cancelImport,
  QUERY_KEYS,
} from "../api/client";
import "./ImportRulesWizard.css";

// Step indicators for the 3-step wizard
function ImportStepIndicators({ currentStep }) {
  const steps = [
    { key: "fetch", label: "Fetch", icon: Download },
    { key: "review", label: "Review", icon: Eye },
    { key: "apply", label: "Apply", icon: Check },
  ];

  const currentIndex = steps.findIndex((s) => s.key === currentStep);

  return (
    <div className="flex items-center justify-center gap-2 mb-6">
      {steps.map((step, idx) => {
        const Icon = step.icon;
        const isActive = step.key === currentStep;
        const isCompleted = idx < currentIndex;

        return (
          <div key={step.key} className="flex items-center">
            <div
              className={`
                flex items-center justify-center w-8 h-8 rounded-none text-sm font-medium
                ${
                  isActive
                    ? "bg-purple-active text-white"
                    : isCompleted
                      ? "bg-green-500 text-white"
                      : "bg-gray-200 dark:bg-charcoal-darkest text-gray-500 dark:text-amber-muted"
                }
              `}
            >
              {isCompleted ? (
                <Check className="w-4 h-4" />
              ) : (
                <Icon className="w-4 h-4" />
              )}
            </div>
            <span
              className={`
                ml-1.5 text-xs font-medium
                ${isActive ? "text-purple-active" : "text-gray-500 dark:text-amber-muted"}
              `}
            >
              {step.label}
            </span>
            {idx < steps.length - 1 && (
              <div
                className={`
                  w-8 h-0.5 mx-2
                  ${idx < currentIndex ? "bg-green-500" : "bg-gray-200 dark:bg-charcoal-darkest"}
                `}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

export default function ImportRulesWizard({ peer, onClose, onSuccess }) {
  const qc = useQueryClient();
  const showToast = useToastContext();
  const modalRef = useRef(null);

  useFocusTrap(modalRef, true);

  const [step, setStep] = useState("fetch"); // 'fetch' | 'review' | 'apply'
  const [sessionId, setSessionId] = useState(null);
  const [_session, setSession] = useState(null);
  const [rules, setRules] = useState([]);
  const [groups, setGroups] = useState([]);
  const [peers, setPeers] = useState([]);
  const [services, setServices] = useState([]);
  const [skippedRules, setSkippedRules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [fetchStatus, setFetchStatus] = useState("initiating");
  const [skippedExpanded, setSkippedExpanded] = useState(false);
  const [editingPolicyName, setEditingPolicyName] = useState(null);
  const [applying, setApplying] = useState(false);

  // Ref to track fetch status for timeout check without stale closure
  const fetchStatusRef = useRef(fetchStatus);
  fetchStatusRef.current = fetchStatus;

  // Step 1: Initiate import and poll for status
  useEffect(() => {
    if (step !== "fetch") return;

    let cancelled = false;
    let pollTimer = null;
    let timeoutTimer = null;

    const startImport = async () => {
      try {
        setFetchStatus("initiating");
        setError(null);
        const result = await initiateImport(peer.id);
        if (cancelled) return;

        setSessionId(result.session_id);
        setFetchStatus("pending");

        // Start polling
        const poll = async () => {
          try {
            const s = await getImportSession(result.session_id);
            if (cancelled) return;
            setSession(s);

            if (s.status === "parsed" || s.status === "reviewing") {
              setFetchStatus("parsed");
              // Auto-advance to step 2 after a brief delay
              setTimeout(() => {
                if (!cancelled) setStep("review");
              }, 800);
              return;
            }

            // Continue polling
            pollTimer = setTimeout(poll, 2000);
} catch {
        if (!cancelled) {
          setError("Failed to check import status");
          pollTimer = setTimeout(poll, 2000); // retry
        }
      }
        };

        pollTimer = setTimeout(poll, 2000);

        // Timeout after 60 seconds
        timeoutTimer = setTimeout(() => {
          if (!cancelled && fetchStatusRef.current === "pending") {
            setError(
              "Agent did not respond within 60 seconds. The agent may be offline.",
            );
          }
        }, 60000);
      } catch (err) {
        if (!cancelled) {
          if (err.status === 409) {
            setError("This peer already has an active import session");
          } else if (err.status === 400) {
            setError(err.message || "Import not allowed for this peer");
          } else {
            setError(err.message || "Failed to initiate import");
          }
        }
      }
    };

    startImport();

    return () => {
      cancelled = true;
      if (pollTimer) clearTimeout(pollTimer);
      if (timeoutTimer) clearTimeout(timeoutTimer);
    };
  }, [step, peer.id]);

  // Step 2: Fetch all review data when entering review step
  useEffect(() => {
    if (step !== "review" || !sessionId) return;

    let cancelled = false;

    const fetchData = async () => {
      setLoading(true);
      try {
        const [r, g, p, s, sk] = await Promise.all([
          getImportRules(sessionId),
          getImportGroups(sessionId),
          getImportPeers(sessionId),
          getImportServices(sessionId),
          getImportSkipped(sessionId),
        ]);

        if (!cancelled) {
          setRules(r || []);
          setGroups(g || []);
          setPeers(p || []);
          setServices(s || []);
          setSkippedRules(sk || []);
        }
      } catch (err) {
        if (!cancelled) setError(err.message || "Failed to load import data");
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    fetchData();

    return () => {
      cancelled = true;
    };
  }, [step, sessionId]);

  // Handle cancel/close
  const handleCancel = useCallback(async () => {
    if (sessionId && step !== "apply") {
      try {
        await cancelImport(sessionId);
      } catch {
        // Ignore cancel errors
      }
    }
    onClose();
  }, [sessionId, step, onClose]);

  // Handle Escape key
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape") handleCancel();
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [handleCancel]);

  // Toggle rule approval
  const toggleRuleApproval = useCallback(
    async (rule) => {
      const newStatus = rule.status === "approved" ? "resolved" : "approved";
      try {
        await updateImportRule(sessionId, rule.id, { status: newStatus });
        setRules((prev) =>
          prev.map((r) =>
            r.id === rule.id ? { ...r, status: newStatus } : r,
          ),
        );
      } catch {
        showToast("Failed to update rule", "error");
      }
    },
    [sessionId, showToast],
  );

  // Approve all rules
  const approveAll = useCallback(async () => {
    try {
      const importable = rules.filter((r) => r.status !== "skipped");
      await Promise.all(
        importable.map((r) =>
          updateImportRule(sessionId, r.id, { status: "approved" }),
        ),
      );
      setRules((prev) =>
        prev.map((r) =>
          r.status !== "skipped" ? { ...r, status: "approved" } : r,
        ),
      );
    } catch {
      showToast("Failed to approve all", "error");
    }
  }, [rules, sessionId, showToast]);

  // Reject all rules
  const rejectAll = useCallback(async () => {
    try {
      const importable = rules.filter((r) => r.status !== "skipped");
      await Promise.all(
        importable.map((r) =>
          updateImportRule(sessionId, r.id, { status: "resolved" }),
        ),
      );
      setRules((prev) =>
        prev.map((r) =>
          r.status !== "skipped" ? { ...r, status: "resolved" } : r,
        ),
      );
    } catch {
      showToast("Failed to reject all", "error");
    }
  }, [rules, sessionId, showToast]);

  // Update policy name
  const updatePolicyName = useCallback(
    async (ruleId, name) => {
      try {
        await updateImportRule(sessionId, ruleId, { policy_name: name });
        setRules((prev) =>
          prev.map((r) =>
            r.id === ruleId ? { ...r, policy_name: name } : r,
          ),
        );
      } catch {
        showToast("Failed to update policy name", "error");
      }
    },
    [sessionId, showToast],
  );

  // Toggle mapping approval (groups/peers/services)
  const toggleMappingApproval = useCallback(
    async (type, id, currentStatus) => {
      const newStatus = currentStatus === "approved" ? "rejected" : "approved";
      const updateFn = {
        group: updateImportGroup,
        peer: updateImportPeer,
        service: updateImportService,
      }[type];
      const setter = { group: setGroups, peer: setPeers, service: setServices }[type];

      try {
        await updateFn(sessionId, id, { status: newStatus });
        setter((prev) =>
          prev.map((m) => (m.id === id ? { ...m, status: newStatus } : m)),
        );
      } catch {
        showToast(`Failed to update ${type}`, "error");
      }
    },
    [sessionId, showToast],
  );

  // Apply import
  const handleApply = useCallback(async () => {
    setApplying(true);
    setError(null);
    try {
      await applyImport(sessionId);

      // Invalidate all relevant caches
      qc.invalidateQueries({ queryKey: QUERY_KEYS.peers() });
      qc.invalidateQueries({ queryKey: QUERY_KEYS.groups() });
      qc.invalidateQueries({ queryKey: QUERY_KEYS.services() });
      qc.invalidateQueries({ queryKey: QUERY_KEYS.policies() });
      qc.invalidateQueries({ queryKey: QUERY_KEYS.pendingChanges() });

      showToast("Rules imported successfully!", "success");
      onSuccess?.();
      onClose?.();
    } catch (err) {
      setError(err.message || "Failed to apply import");
    } finally {
      setApplying(false);
    }
  }, [sessionId, qc, showToast, onSuccess, onClose]);

  // Compute counts for step 3 summary
  const approvedRulesCount = rules.filter(
    (r) => r.status === "approved",
  ).length;
  const approvedGroupsCount = groups.filter(
    (g) => g.status === "approved" && !g.existing_group_id,
  ).length;
  const approvedPeersCount = peers.filter(
    (p) => p.status === "approved" && !p.existing_peer_id,
  ).length;
  const approvedServicesCount = services.filter(
    (s) => s.status === "approved" && !s.existing_service_id,
  ).length;

  const importableRules = rules.filter((r) => r.status !== "skipped");
  const skippedCount = skippedRules.length;

  const modalContent = (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center import-wizard-overlay">
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={handleCancel}
      />
      <div
        ref={modalRef}
        className="relative bg-white dark:bg-charcoal-light rounded-xl shadow-2xl w-full max-w-5xl max-h-[90vh] overflow-hidden flex flex-col import-wizard-modal"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-border">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-light-neutral">
            Import Pre-Runic Rules — {peer.hostname}
          </h2>
          <button
            onClick={handleCancel}
            className="p-1 rounded-lg hover:bg-gray-100 dark:hover:bg-charcoal-darkest"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        {/* Step Indicators */}
        <div className="px-6 pt-4">
          <ImportStepIndicators currentStep={step} />
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-6 py-4">
          {error && (
            <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-center gap-2">
              <AlertCircle className="w-5 h-5 text-red-500 shrink-0" />
              <span className="text-red-700 dark:text-red-300">{error}</span>
            </div>
          )}

          {/* STEP 1: Fetch & Parse */}
          {step === "fetch" && (
            <div className="flex flex-col items-center justify-center py-16 gap-4">
              <Loader2 className="w-12 h-12 text-blue-500 animate-spin" />
              <p className="text-lg text-gray-600 dark:text-gray-300">
                {fetchStatus === "initiating" &&
                  "Sending request to agent..."}
                {fetchStatus === "pending" &&
                  "Waiting for agent to send backup..."}
                {fetchStatus === "parsed" &&
                  "Rules parsed! Loading review..."}
              </p>
              <p className="text-sm text-gray-400">
                This may take a few seconds
              </p>
            </div>
          )}

          {/* STEP 2: Review & Configure */}
          {step === "review" && (
            <div className="space-y-6">
              {loading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
                </div>
              ) : (
                <>
                  {/* Summary Stats */}
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div className="flex gap-4 text-sm flex-wrap">
                      <span className="text-gray-600 dark:text-gray-300">
                        <strong className="text-gray-900 dark:text-light-neutral">
                          {importableRules.length}
                        </strong>{" "}
                        importable rules
                      </span>
                      <span className="text-orange-600 dark:text-orange-400">
                        <strong>{skippedCount}</strong> skipped
                      </span>
                      <span className="text-purple-600 dark:text-purple-400">
                        <strong>
                          {groups.filter((g) => !g.existing_group_id).length}
                        </strong>{" "}
                        new groups
                      </span>
                      <span className="text-teal-600 dark:text-teal-400">
                        <strong>
                          {peers.filter((p) => !p.existing_peer_id).length}
                        </strong>{" "}
                        new peers
                      </span>
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={approveAll}
                        className="px-3 py-1.5 text-sm bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 rounded-lg hover:bg-green-200"
                      >
                        Approve All
                      </button>
                      <button
                        onClick={rejectAll}
                        className="px-3 py-1.5 text-sm bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 rounded-lg hover:bg-red-200"
                      >
                        Reject All
                      </button>
                    </div>
                  </div>

                  {/* Rules Table */}
                  {importableRules.length > 0 && (
                    <div className="overflow-x-auto border border-gray-200 dark:border-gray-border rounded-lg">
                      <table className="w-full text-sm">
                        <thead className="bg-gray-50 dark:bg-charcoal-darkest">
                          <tr>
                            <th className="px-3 py-2 text-left w-10"></th>
                            <th className="px-3 py-2 text-left">Chain</th>
                            <th className="px-3 py-2 text-left">Rule</th>
                            <th className="px-3 py-2 text-left">Source</th>
                            <th className="px-3 py-2 text-left">Target</th>
                            <th className="px-3 py-2 text-left">Service</th>
                            <th className="px-3 py-2 text-left">Action</th>
                            <th className="px-3 py-2 text-left">
                              Policy Name
                            </th>
                            <th className="px-3 py-2 text-left">Dir</th>
                            <th className="px-3 py-2 text-left">Scope</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-100 dark:divide-gray-border">
                          {importableRules.map((rule) => (
                            <tr
                              key={rule.id}
                              className={`hover:bg-gray-50 dark:hover:bg-charcoal-darkest ${
                                rule.status === "approved"
                                  ? "bg-green-50/50 dark:bg-green-900/10"
                                  : ""
                              }`}
                            >
                              <td className="px-3 py-2">
                                <input
                                  type="checkbox"
                                  checked={rule.status === "approved"}
                                  onChange={() => toggleRuleApproval(rule)}
                                  className="w-4 h-4 rounded"
                                />
                              </td>
                              <td className="px-3 py-2">
                                <span
                                  className={`px-2 py-0.5 rounded text-xs font-medium ${
                                    rule.chain === "DOCKER-USER"
                                      ? "bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400"
                                      : rule.chain === "INPUT"
                                        ? "bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400"
                                        : "bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-400"
                                  }`}
                                >
                                  {rule.chain}
                                </span>
                              </td>
                              <td
                                className="px-3 py-2 font-mono text-xs text-gray-500 dark:text-gray-400 max-w-[200px] truncate"
                                title={rule.raw_rule}
                              >
                                {rule.raw_rule}
                              </td>
                              <td className="px-3 py-2 text-gray-700 dark:text-gray-300">
                                {rule.source_name || "—"}
                              </td>
                              <td className="px-3 py-2 text-gray-700 dark:text-gray-300">
                                {rule.target_name || "—"}
                              </td>
                              <td className="px-3 py-2 text-gray-700 dark:text-gray-300">
                                {rule.service_name || "—"}
                              </td>
                              <td className="px-3 py-2">
                                <span
                                  className={`px-2 py-0.5 rounded text-xs font-medium ${
                                    rule.action === "ACCEPT"
                                      ? "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400"
                                      : "bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400"
                                  }`}
                                >
                                  {rule.action}
                                </span>
                              </td>
                              <td className="px-3 py-2">
                                {editingPolicyName === rule.id ? (
                                  <input
                                    type="text"
                                    defaultValue={rule.policy_name}
                                    className="w-full px-1 py-0.5 text-xs border border-blue-400 rounded bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                                    autoFocus
                                    onBlur={(e) => {
                                      updatePolicyName(
                                        rule.id,
                                        e.target.value,
                                      );
                                      setEditingPolicyName(null);
                                    }}
                                    onKeyDown={(e) => {
                                      if (e.key === "Enter") {
                                        updatePolicyName(
                                          rule.id,
                                          e.target.value,
                                        );
                                        setEditingPolicyName(null);
                                      }
                                    }}
                                  />
                                ) : (
                                  <span
                                    className="text-xs text-gray-700 dark:text-gray-300 cursor-pointer hover:text-blue-600 dark:hover:text-blue-400"
                                    onClick={() =>
                                      setEditingPolicyName(rule.id)
                                    }
                                  >
                                    {rule.policy_name || "—"}
                                  </span>
                                )}
                              </td>
                              <td className="px-3 py-2">
                                {rule.direction === "forward" ? (
                                  <ArrowRight className="w-4 h-4 text-blue-500" />
                                ) : rule.direction === "backward" ? (
                                  <ArrowLeft className="w-4 h-4 text-purple-500" />
                                ) : (
                                  <MoveHorizontal className="w-4 h-4 text-gray-400" />
                                )}
                              </td>
                              <td className="px-3 py-2">
                                <span
                                  className={`px-2 py-0.5 rounded text-xs ${
                                    rule.target_scope === "docker"
                                      ? "bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400"
                                      : "bg-gray-100 dark:bg-charcoal-darkest text-gray-600 dark:text-gray-300"
                                  }`}
                                >
                                  {rule.target_scope || "host"}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {importableRules.length === 0 && skippedCount === 0 && (
                    <p className="text-center text-gray-500 dark:text-gray-400 py-4">
                      No importable rules found.
                    </p>
                  )}

                  {/* New Groups Section */}
                  {groups.filter((g) => !g.existing_group_id).length > 0 && (
                    <div className="border border-gray-200 dark:border-gray-border rounded-lg p-4">
                      <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3 flex items-center gap-2">
                        <Users className="w-4 h-4" />
                        New Groups
                      </h3>
                      <div className="space-y-2">
                        {groups
                          .filter((g) => !g.existing_group_id)
                          .map((g) => (
                            <div
                              key={g.id}
                              className="flex items-center gap-3 p-2 bg-gray-50 dark:bg-charcoal-darkest rounded"
                            >
                              <input
                                type="checkbox"
                                checked={g.status === "approved"}
                                onChange={() =>
                                  toggleMappingApproval(
                                    "group",
                                    g.id,
                                    g.status,
                                  )
                                }
                                className="w-4 h-4 rounded"
                              />
                              <div className="flex-1 min-w-0">
                                <span className="text-sm font-medium text-gray-900 dark:text-light-neutral">
                                  {g.group_name}
                                </span>
                                {g.member_ips && g.member_ips.length > 0 && (
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {g.member_ips.map((ip, i) => (
                                      <span
                                        key={i}
                                        className="px-1.5 py-0.5 bg-gray-200 dark:bg-charcoal-darker text-xs rounded font-mono text-gray-700 dark:text-gray-300"
                                      >
                                        {ip}
                                      </span>
                                    ))}
                                  </div>
                                )}
                              </div>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}

                  {/* New Peers Section */}
                  {peers.filter((p) => !p.existing_peer_id).length > 0 && (
                    <div className="border border-gray-200 dark:border-gray-border rounded-lg p-4">
                      <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3 flex items-center gap-2">
                        <Server className="w-4 h-4" />
                        New Peers
                      </h3>
                      <div className="space-y-2">
                        {peers
                          .filter((p) => !p.existing_peer_id)
                          .map((p) => (
                            <div
                              key={p.id}
                              className="flex items-center gap-3 p-2 bg-gray-50 dark:bg-charcoal-darkest rounded"
                            >
                              <input
                                type="checkbox"
                                checked={p.status === "approved"}
                                onChange={() =>
                                  toggleMappingApproval(
                                    "peer",
                                    p.id,
                                    p.status,
                                  )
                                }
                                className="w-4 h-4 rounded"
                              />
                              <div>
                                <span className="text-sm font-medium text-gray-900 dark:text-light-neutral">
                                  {p.hostname || p.ip_address}
                                </span>
                                <span className="ml-2 text-xs text-gray-500 font-mono">
                                  {p.ip_address}
                                </span>
                              </div>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}

                  {/* New Services Section */}
                  {services.filter((s) => !s.existing_service_id).length > 0 && (
                    <div className="border border-gray-200 dark:border-gray-border rounded-lg p-4">
                      <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3 flex items-center gap-2">
                        <Package className="w-4 h-4" />
                        New Services
                      </h3>
                      <div className="space-y-2">
                        {services
                          .filter((s) => !s.existing_service_id)
                          .map((s) => (
                            <div
                              key={s.id}
                              className="flex items-center gap-3 p-2 bg-gray-50 dark:bg-charcoal-darkest rounded"
                            >
                              <input
                                type="checkbox"
                                checked={s.status === "approved"}
                                onChange={() =>
                                  toggleMappingApproval(
                                    "service",
                                    s.id,
                                    s.status,
                                  )
                                }
                                className="w-4 h-4 rounded"
                              />
                              <div>
                                <span className="text-sm font-medium text-gray-900 dark:text-light-neutral">
                                  {s.name}
                                </span>
                                <span className="ml-2 text-xs text-gray-500">
                                  Port {s.ports} ({s.protocol})
                                </span>
                              </div>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}

                  {/* Skipped Rules Section (collapsed) */}
                  {skippedCount > 0 && (
                    <div className="border border-gray-200 dark:border-gray-border rounded-lg">
                      <button
                        className="w-full flex items-center justify-between p-4 text-left"
                        onClick={() => setSkippedExpanded(!skippedExpanded)}
                      >
                        <span className="text-sm font-semibold text-orange-600 dark:text-orange-400">
                          {skippedCount} rules couldn&apos;t be imported
                        </span>
                        {skippedExpanded ? (
                          <ChevronUp className="w-4 h-4" />
                        ) : (
                          <ChevronDown className="w-4 h-4" />
                        )}
                      </button>
                      {skippedExpanded && (
                        <div className="px-4 pb-4 space-y-2">
                          {skippedRules.map((sr) => (
                            <div
                              key={sr.id}
                              className="p-2 bg-orange-50 dark:bg-orange-900/10 rounded text-xs"
                            >
                              <div className="font-mono text-gray-700 dark:text-gray-300 break-all">
                                {sr.raw_rule}
                              </div>
                              <div className="text-orange-600 dark:text-orange-400 mt-1">
                                Reason: {sr.skip_reason}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {/* STEP 3: Apply */}
          {step === "apply" && (
            <div className="py-8 space-y-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral text-center">
                Confirm Import
              </h3>
              <div className="max-w-md mx-auto space-y-3">
                <div className="flex justify-between p-3 bg-gray-50 dark:bg-charcoal-darkest rounded-lg">
                  <span className="text-gray-600 dark:text-gray-300">
                    Policies to create
                  </span>
                  <span className="font-semibold text-gray-900 dark:text-light-neutral">
                    {approvedRulesCount}
                  </span>
                </div>
                <div className="flex justify-between p-3 bg-gray-50 dark:bg-charcoal-darkest rounded-lg">
                  <span className="text-gray-600 dark:text-gray-300">
                    New groups
                  </span>
                  <span className="font-semibold text-gray-900 dark:text-light-neutral">
                    {approvedGroupsCount}
                  </span>
                </div>
                <div className="flex justify-between p-3 bg-gray-50 dark:bg-charcoal-darkest rounded-lg">
                  <span className="text-gray-600 dark:text-gray-300">
                    New manual peers
                  </span>
                  <span className="font-semibold text-gray-900 dark:text-light-neutral">
                    {approvedPeersCount}
                  </span>
                </div>
                <div className="flex justify-between p-3 bg-gray-50 dark:bg-charcoal-darkest rounded-lg">
                  <span className="text-gray-600 dark:text-gray-300">
                    New services
                  </span>
                  <span className="font-semibold text-gray-900 dark:text-light-neutral">
                    {approvedServicesCount}
                  </span>
                </div>
              </div>
              {approvedRulesCount === 0 && (
                <p className="text-center text-orange-600 dark:text-orange-400 text-sm">
                  No rules are approved. Go back and approve at least one rule.
                </p>
              )}
            </div>
          )}
        </div>

        {/* Footer with navigation buttons */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-gray-200 dark:border-gray-border">
          <div>
            {step === "fetch" && (
              <button
                onClick={handleCancel}
                className="px-4 py-2 text-sm text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-lg"
              >
                Cancel
              </button>
            )}
            {step === "review" && (
              <button
                onClick={() => setStep("fetch")}
                className="flex items-center gap-2 px-4 py-2 text-sm text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-lg"
              >
                <ChevronLeft className="w-4 h-4" />
                Back
              </button>
            )}
            {step === "apply" && (
              <button
                onClick={() => setStep("review")}
                className="flex items-center gap-2 px-4 py-2 text-sm text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-lg"
              >
                <ChevronLeft className="w-4 h-4" />
                Back
              </button>
            )}
          </div>
          <div className="flex gap-3">
            {step === "fetch" && (
              <button
                onClick={handleCancel}
                className="px-4 py-2 text-sm bg-gray-200 dark:bg-charcoal-darkest text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300"
              >
                Cancel
              </button>
            )}
            {step === "review" && (
              <button
                onClick={() => setStep("apply")}
                className="flex items-center gap-2 px-6 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Next
                <ChevronRight className="w-4 h-4" />
              </button>
            )}
            {step === "apply" && (
              <button
                onClick={handleApply}
                disabled={applying || approvedRulesCount === 0}
                className="flex items-center gap-2 px-6 py-2 text-sm bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {applying ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Check className="w-4 h-4" />
                )}
                {applying ? "Applying..." : "Apply Import"}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );

  return ReactDOM.createPortal(modalContent, document.body);
}
