import { useMemo } from 'react'
import { Pencil, Trash2, ArrowRight, ArrowLeft } from 'lucide-react'
import ToggleSwitch from './ToggleSwitch'
import SortIndicator from './SortIndicator'
import Pagination from './Pagination'
import EmptyState from './EmptyState'
import KebabMenu from './KebabMenu'

export default function PolicyTable({
  policies,
  paginatedPolicies,
  sortConfig,
  onSort,
  onEdit,
  onDelete,
  canEdit,
  searchTerm,
  showPendingDeletes,
  setShowPendingDeletes,
  toggleMutation,
  getEntityName,
  getServiceName,
  openAdd,
  // Pagination props
  showingRange,
  page,
  totalPages,
  onPageChange,
  totalItems,
}) {
  const hasPendingDeletes = useMemo(
    () => policies?.some(p => p.is_pending_delete),
    [policies]
  )

  if (!policies?.length && !searchTerm) {
    return (
      <EmptyState
        title="No policies yet"
        message="Create policies to define firewall rules for your servers."
        action="New Policy"
        onAction={openAdd}
      />
    )
  }

  if (!paginatedPolicies?.length) {
    return (
      <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none p-8 text-center">
        <p className="text-gray-500 dark:text-amber-muted">No policies match your search.</p>
      </div>
    )
  }

  return (
    <div className="border border-gray-200 dark:border-gray-border overflow-hidden">
      {/* Pending deletes checkbox */}
      {hasPendingDeletes && (
        <div className="px-4 py-2 bg-white dark:bg-charcoal-dark border-b border-gray-200 dark:border-gray-border flex items-center gap-2">
          <input
            type="checkbox"
            id="showPendingDeletes"
            checked={showPendingDeletes}
            onChange={(e) => setShowPendingDeletes(e.target.checked)}
            className="w-4 h-4 text-purple-active bg-gray-100 border-gray-300 rounded-none focus:ring-purple-active dark:focus:ring-purple-active dark:ring-offset-gray-800 focus:ring-2 dark:bg-charcoal-darkest dark:border-gray-600"
          />
          <label htmlFor="showPendingDeletes" className="text-sm text-gray-700 dark:text-amber-primary cursor-pointer">
            Show Pending Deletes
          </label>
        </div>
      )}

      {/* Mobile Card View */}
      <div className="md:hidden divide-y divide-gray-200 dark:divide-gray-border">
        {paginatedPolicies.map((p) => (
          <div key={p.id} className="bg-white dark:bg-charcoal-dark p-4">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-3 min-w-0 flex-1">
                <ToggleSwitch
                  checked={p.enabled}
                  onChange={(v) => toggleMutation.mutate({ id: p.id, enabled: v })}
                  aria-labelledby={`policy-${p.id}-enabled-label`}
                />
                <span id={`policy-${p.id}-enabled-label`} className="sr-only">{p.name} policy enabled</span>
                <div className="min-w-0 flex-1">
                  <span className="font-medium text-gray-900 dark:text-light-neutral truncate block">
                    {p.name}
                    {p.is_pending_delete && (
                      <span className="ml-2 px-2 py-1 text-xs bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300 rounded-none">
                        Pending Delete
                      </span>
                    )}
                  </span>
                  <div className="text-sm text-gray-500 dark:text-amber-muted truncate mt-1">
                    {getEntityName(p.source_type, p.source_id, p.source_ip)} → {getEntityName(p.target_type, p.target_id, p.target_ip)} : {getServiceName(p.service_id)}
                  </div>
                </div>
              </div>
              {canEdit && (
                <KebabMenu
                  items={[
                    {
                      label: 'Edit',
                      icon: Pencil,
                      onClick: () => onEdit(p),
                      show: !p.is_pending_delete,
                    },
                    {
                      label: 'Delete',
                      icon: Trash2,
                      onClick: () => onDelete(p),
                      danger: true,
                      show: !p.is_pending_delete,
                    },
                  ]}
                />
              )}
            </div>
          </div>
        ))}
        <Pagination showingRange={showingRange} page={page} totalPages={totalPages} onPageChange={onPageChange} totalItems={totalItems} />
      </div>

      {/* Desktop Table View */}
      <div className="hidden md:block overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 dark:bg-charcoal-darkest border-b border-gray-200 dark:border-gray-border">
            <tr>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider">
                Enabled
              </th>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                <button type="button" onClick={() => onSort('name')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                  Name <SortIndicator columnKey="name" sortConfig={sortConfig} />
                </button>
              </th>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                <button type="button" onClick={() => onSort('priority')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                  Priority <SortIndicator columnKey="priority" sortConfig={sortConfig} />
                </button>
              </th>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                <button type="button" onClick={() => onSort('source')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                  Source <SortIndicator columnKey="source" sortConfig={sortConfig} />
                </button>
              </th>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                <button type="button" onClick={() => onSort('service')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                  Service <SortIndicator columnKey="service" sortConfig={sortConfig} />
                </button>
              </th>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                <button type="button" onClick={() => onSort('target')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                  Target <SortIndicator columnKey="target" sortConfig={sortConfig} />
                </button>
              </th>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider">
                Action
              </th>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider">
                Direction
              </th>
              <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-border">
            {paginatedPolicies.map((p) => (
              <tr key={p.id}>
                <td className="px-4 py-1">
                  <ToggleSwitch checked={p.enabled} onChange={(v) => toggleMutation.mutate({ id: p.id, enabled: v })} aria-labelledby={`policy-${p.id}-enabled-label`} />
                  <span id={`policy-${p.id}-enabled-label`} className="sr-only">{p.name} policy enabled</span>
                </td>
                <td className="px-4 py-1">
                  <span className="font-medium text-gray-900 dark:text-light-neutral">
                    {p.name}
                    {p.is_pending_delete && (
                      <span className="ml-2 px-2 py-1 text-xs bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300 rounded-none">
                        Pending Delete
                      </span>
                    )}
                  </span>
                </td>
                <td className="px-4 py-1 font-mono text-gray-600 dark:text-amber-primary">
                  {p.priority}
                </td>
                <td className="px-4 py-1 text-gray-600 dark:text-amber-primary">
                  {getEntityName(p.source_type, p.source_id, p.source_ip)}
                </td>
                <td className="px-4 py-1 text-gray-600 dark:text-amber-primary">
                  {getServiceName(p.service_id)}
                </td>
                <td className="px-4 py-1 text-gray-600 dark:text-amber-primary">
                  {getEntityName(p.target_type, p.target_id, p.target_ip)}
                </td>
                <td className="px-4 py-1">
                  <span className={`px-2 py-0.5 text-xs font-medium ${p.action === 'ACCEPT' ? 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300'}`}>
                    {p.action.toUpperCase()}
                  </span>
                </td>
                <td className="px-4 py-1">
                  <div className="flex items-center gap-1">
                    {(p.direction === 'both' || p.direction === 'forward') && (
                      <span className="inline-flex items-center px-1.5 py-0.5 text-xs font-medium bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-400" title="Forward (Source → Target)">
                        <ArrowRight className="w-3 h-3" />
                      </span>
                    )}
                    {(p.direction === 'both' || p.direction === 'backward') && (
                      <span className="inline-flex items-center px-1.5 py-0.5 text-xs font-medium bg-blue-100 text-blue-600 dark:bg-blue-900/40 dark:text-blue-400" title="Backward (Target → Source)">
                        <ArrowLeft className="w-3 h-3" />
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-1">
                  <div className="flex items-center gap-2">
                    {canEdit && (
                      <button
                        onClick={() => onEdit(p)}
                        className={`p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none ${p.is_pending_delete ? 'text-gray-400 cursor-not-allowed opacity-50' : ''}`}
                        disabled={p.is_pending_delete}
                        title={p.is_pending_delete ? "Cannot edit soft-deleted policies" : "Edit"}
                      >
                        <Pencil className={`w-4 h-4 ${p.is_pending_delete ? 'text-gray-400' : 'text-gray-500'}`} />
                      </button>
                    )}
                    {canEdit && (
                      <button
                        onClick={() => !p.is_pending_delete && onDelete(p)}
                        disabled={p.is_pending_delete}
                        className={`p-1.5 rounded-none ${p.is_pending_delete ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-100 dark:hover:bg-charcoal-darkest'}`}
                        title={p.is_pending_delete ? "Cannot delete soft-deleted policies" : "Delete"}
                      >
                        <Trash2 className="w-4 h-4 text-red-500" />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Pagination showingRange={showingRange} page={page} totalPages={totalPages} onPageChange={onPageChange} totalItems={totalItems} />
    </div>
  )
}
