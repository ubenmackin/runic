import { Fragment } from "react";
import {
  Loader2,
  Shield,
  Users,
  Server,
  Package,
  ArrowRight,
  ArrowLeft,
  MoveHorizontal,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
} from "lucide-react";

export default function ReviewContent({
  loading,
  importableRules,
  toggleRuleApproval,
  approveAll,
  rejectAll,
  groups,
  peers,
  services,
  skippedRules,
  skippedCount,
  skippedExpanded,
  setSkippedExpanded,
  expandedRule,
  toggleRuleExpand,
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  return (
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
                <span className="text-indigo-600 dark:text-indigo-400">
                  <strong>
                    {services.filter((s) => !s.existing_service_id).length}
                  </strong>{" "}
                  new services
                </span>
              </div>
        <div className="flex gap-2">
          <button
            onClick={approveAll}
            className="px-3 py-1.5 text-sm bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 rounded-none hover:bg-green-200"
          >
            Approve All
          </button>
          <button
            onClick={rejectAll}
            className="px-3 py-1.5 text-sm bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 rounded-none hover:bg-red-200"
          >
            Reject All
          </button>
        </div>
      </div>

  {/* Rules Table */}
  {importableRules.length > 0 && (
    <div className="border border-gray-200 dark:border-gray-border rounded-none p-4">
      <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3 flex items-center gap-2">
        <Shield className="w-4 h-4" />
        New Policies
      </h3>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 dark:bg-charcoal-darkest border-b border-gray-200 dark:border-gray-border">
            <tr>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                {""}
              </th>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                Approve
              </th>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                Chain
              </th>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                Source
              </th>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                Direction
              </th>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                Target
              </th>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                Service
              </th>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                Action
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 dark:divide-gray-border">
            {importableRules.map((rule) => (
              <Fragment key={rule.id}>
                <tr
                  className={`hover:bg-gray-50 dark:hover:bg-charcoal-darkest ${
                    rule.status === "approved"
                      ? "bg-green-50/50 dark:bg-green-900/10"
                      : ""
                  }`}
                >
                  <td className="px-4 py-1 text-center w-10">
                    <button
                      onClick={() => toggleRuleExpand(rule.id)}
                      className="p-0.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest"
                    >
                      {expandedRule === rule.id ? (
                        <ChevronUp className="w-4 h-4 text-gray-500" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-gray-500" />
                      )}
                    </button>
                  </td>
                  <td className="px-4 py-1">
                    <input
                      type="checkbox"
                      checked={rule.status === "approved"}
                      onChange={() => toggleRuleApproval(rule)}
                      className="w-4 h-4 rounded-none"
                    />
                  </td>
                  <td className="px-4 py-1">
                    <span
                      className={`px-2 py-0.5 rounded-none text-xs font-medium ${
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
                  <td className="px-4 py-1 text-gray-700 dark:text-gray-300">
                    {rule.source_name || "—"}
                  </td>
                  <td className="px-4 py-1">
                    {rule.direction === "forward" ? (
                      <ArrowRight className="w-4 h-4 text-green-500" />
                    ) : rule.direction === "backward" ? (
                      <ArrowLeft className="w-4 h-4 text-blue-500" />
                    ) : (
                      <MoveHorizontal className="w-4 h-4 text-gray-400" />
                    )}
                  </td>
                  <td className="px-4 py-1 text-gray-700 dark:text-gray-300">
                    {rule.target_name || "—"}
                  </td>
                  <td className="px-4 py-1 text-gray-700 dark:text-gray-300">
                    {rule.service_name || "—"}
                  </td>
                  <td className="px-4 py-1">
                    <span
                      className={`px-2 py-0.5 rounded-none text-xs font-medium ${
                        rule.action === "ACCEPT"
                          ? "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400"
                          : "bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400"
                      }`}
                    >
                      {rule.action}
                    </span>
                  </td>
                </tr>
                {expandedRule === rule.id && (
                  <tr className="bg-gray-50 dark:bg-charcoal-darkest">
                    <td colSpan={8} className="px-4 py-3">
                      <div className="font-mono text-xs text-gray-600 dark:text-gray-400 whitespace-pre-wrap break-all">
                        {rule.raw_rule}
                      </div>
                      {rule.description && (
                        <div className="mt-2 text-xs text-gray-500 dark:text-gray-400">
                          Comment: {rule.description}
                        </div>
                      )}
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )}

      {importableRules.length === 0 && skippedCount === 0 && (
        <p className="text-center text-gray-500 dark:text-gray-400 py-4">
          No importable rules found.
        </p>
      )}

      {/* New Groups Section */}
      {groups.filter((g) => !g.existing_group_id).length > 0 && (
        <div className="border border-gray-200 dark:border-gray-border rounded-none p-4">
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
    className="flex items-center gap-3 p-2 bg-gray-50 dark:bg-charcoal-darkest rounded-none"
  >
    <div className="flex-1 min-w-0">
                  <span className="text-sm font-medium text-gray-900 dark:text-light-neutral">
                    {g.group_name}
                  </span>
                  {g.member_ips && g.member_ips.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1">
                      {g.member_ips.map((ip, i) => (
                        <span
                          key={i}
                          className="px-1.5 py-0.5 bg-gray-200 dark:bg-charcoal-darkest text-xs rounded-none font-mono text-gray-700 dark:text-gray-300"
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
        <div className="border border-gray-200 dark:border-gray-border rounded-none p-4">
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
    className="flex items-center gap-3 p-2 bg-gray-50 dark:bg-charcoal-darkest rounded-none"
  >
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
        <div className="border border-gray-200 dark:border-gray-border rounded-none p-4">
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
    className="flex items-center gap-3 p-2 bg-gray-50 dark:bg-charcoal-darkest rounded-none"
  >
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
        <div className="border border-gray-200 dark:border-gray-border rounded-none">
          <button
            className="w-full flex items-center justify-between p-4 text-left"
            onClick={() => setSkippedExpanded(!skippedExpanded)}
          >
<h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 flex items-center gap-2">
<AlertTriangle className="w-4 h-4" />
Skipped Rules
<span className="text-xs font-normal text-gray-500 dark:text-gray-400">({skippedCount})</span>
</h3>
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
                  className="p-2 bg-orange-50 dark:bg-orange-900/10 rounded-none text-xs"
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
  );
}
