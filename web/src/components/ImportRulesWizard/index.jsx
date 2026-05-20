import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import ReactDOM from "react-dom";
import {
  X,
  ChevronLeft,
  ChevronRight,
  Check,
  Loader2,
  AlertCircle,
  Download,
  Eye,
} from "lucide-react";
import { useToastContext } from "../../hooks/ToastContext";
import { useFocusTrap } from "../../hooks/useFocusTrap";
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
  applyImport,
  cancelImport,
  QUERY_KEYS,
} from "../../api/client";
import StepIndicator from "../StepIndicator";
import FetchStep from "./FetchStep";
import ReviewContent from "./ReviewContent";
import ApplyStep from "./ApplyStep";

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
  const [applying, setApplying] = useState(false);
  const [expandedRule, setExpandedRule] = useState(null);

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

  const toggleRuleExpand = (id) => setExpandedRule(expandedRule === id ? null : id);

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
  const approvedRulesCount = useMemo(
    () => rules.filter((r) => r.status === "approved").length,
    [rules],
  );
  // Get IDs of entities referenced by approved rules
  const approvedRuleSourceStagingIds = useMemo(
    () => rules.filter(r => r.status === "approved").map(r => r.source_staging_id).filter(Boolean),
    [rules],
  );
  const approvedRuleTargetStagingIds = useMemo(
    () => rules.filter(r => r.status === "approved").map(r => r.target_staging_id).filter(Boolean),
    [rules],
  );
  const approvedRuleServiceStagingIds = useMemo(
    () => rules.filter(r => r.status === "approved").map(r => r.service_staging_id).filter(Boolean),
    [rules],
  );

  const approvedGroupsCount = useMemo(
    () => groups.filter(g => !g.existing_group_id && (approvedRuleTargetStagingIds.includes(g.id) || approvedRuleSourceStagingIds.includes(g.id))).length,
    [groups, approvedRuleTargetStagingIds, approvedRuleSourceStagingIds],
  );
  const approvedPeersCount = useMemo(
    () => peers.filter(p => !p.existing_peer_id && (approvedRuleTargetStagingIds.includes(p.id) || approvedRuleSourceStagingIds.includes(p.id))).length,
    [peers, approvedRuleTargetStagingIds, approvedRuleSourceStagingIds],
  );
  const approvedServicesCount = useMemo(
    () => services.filter(s => !s.existing_service_id && (approvedRuleServiceStagingIds.includes(s.id))).length,
    [services, approvedRuleServiceStagingIds],
  );

  const importableRules = useMemo(
    () => rules.filter((r) => r.status !== "skipped"),
    [rules],
  );
  const skippedCount = useMemo(() => skippedRules.length, [skippedRules]);

  const modalContent = (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center animate-import-wizard-fade-in">
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={handleCancel}
      />
      <div
        ref={modalRef}
        className="relative bg-white dark:bg-charcoal-dark rounded-none shadow-none w-full max-w-5xl max-h-[90vh] overflow-hidden flex flex-col animate-import-wizard-slide-up"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-border">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-light-neutral">
            Import Pre-Runic Rules — {peer.hostname}
          </h2>
          <button
            onClick={handleCancel}
            className="p-1 rounded-none hover:bg-gray-100 dark:hover:bg-charcoal-darkest"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        {/* Step Indicators */}
        <div className="px-6 pt-4">
          <StepIndicator
            steps={[
              { key: "fetch", label: "Fetch", icon: Download },
              { key: "review", label: "Review", icon: Eye },
              { key: "apply", label: "Apply", icon: Check },
            ]}
            currentStep={step}
          />
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-6 py-4">
          {error && (
            <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-none flex items-center gap-2">
              <AlertCircle className="w-5 h-5 text-red-500 shrink-0" />
              <span className="text-red-700 dark:text-red-300">{error}</span>
            </div>
          )}

          {/* STEP 1: Fetch & Parse */}
          {step === "fetch" && (
            <FetchStep fetchStatus={fetchStatus} />
          )}

          {/* STEP 2: Review & Configure */}
          {step === "review" && (
            <div className="space-y-6">
              <ReviewContent
                loading={loading}
                importableRules={importableRules}
                rules={rules}
                toggleRuleApproval={toggleRuleApproval}
                approveAll={approveAll}
                rejectAll={rejectAll}
                groups={groups}
                peers={peers}
                services={services}
                skippedRules={skippedRules}
                skippedCount={skippedCount}
                skippedExpanded={skippedExpanded}
                setSkippedExpanded={setSkippedExpanded}
                expandedRule={expandedRule}
                toggleRuleExpand={toggleRuleExpand}
              />
            </div>
          )}

          {/* STEP 3: Apply */}
          {step === "apply" && (
            <ApplyStep
              approvedRulesCount={approvedRulesCount}
              approvedGroupsCount={approvedGroupsCount}
              approvedPeersCount={approvedPeersCount}
              approvedServicesCount={approvedServicesCount}
            />
          )}
        </div>

        {/* Footer with navigation buttons */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-gray-200 dark:border-gray-border">
          <div>
            {step === "fetch" && (
              <button
                onClick={handleCancel}
                className="px-4 py-2 text-sm text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none"
              >
                Cancel
              </button>
            )}
            {step === "review" && (
              <button
onClick={() => setStep("fetch")}
className="flex items-center gap-2 px-4 py-2 text-sm text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none"
              >
                <ChevronLeft className="w-4 h-4" />
                Back
              </button>
            )}
            {step === "apply" && (
              <button
onClick={() => setStep("review")}
className="flex items-center gap-2 px-4 py-2 text-sm text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none"
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
                className="px-4 py-2 text-sm bg-gray-200 dark:bg-charcoal-darkest text-gray-700 dark:text-gray-300 rounded-none hover:bg-gray-300"
              >
                Cancel
              </button>
            )}
            {step === "review" && (
              <button
                onClick={() => setStep("apply")}
                className="flex items-center gap-2 px-6 py-2 text-sm bg-blue-600 text-white rounded-none hover:bg-blue-700"
              >
                Next
                <ChevronRight className="w-4 h-4" />
              </button>
            )}
            {step === "apply" && (
              <button
                onClick={handleApply}
                disabled={applying || approvedRulesCount === 0}
                className="flex items-center gap-2 px-6 py-2 text-sm bg-green-600 text-white rounded-none hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
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
