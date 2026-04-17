import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bell, Calendar, X, Trash2, AlertTriangle, Info, ChevronUp, ChevronDown } from 'lucide-react'
import { api, QUERY_KEYS, deleteAlert, clearAllAlerts } from '../api/client'
import { useAuth } from '../hooks/useAuth'
import { useToastContext } from '../hooks/ToastContext'
import { useFocusTrap } from '../hooks/useFocusTrap'
import { useTableSort } from '../hooks/useTableSort'
import { useFilterPersistence } from '../hooks/useFilterPersistence'
import PageHeader from '../components/PageHeader'
import Pagination from '../components/Pagination'
import EmptyState from '../components/EmptyState'
import TableSkeleton from '../components/TableSkeleton'
import SearchFilterPanel from '../components/SearchFilterPanel'
import SortIndicator from '../components/SortIndicator'
import MultiSelect from '../components/MultiSelect'

const ALERT_TYPES = [
  { value: 'bundle_deployed', label: 'Bundle Deployed' },
  { value: 'bundle_failed', label: 'Bundle Failed' },
  { value: 'peer_offline', label: 'Peer Offline' },
  { value: 'peer_online', label: 'Peer Online' },
  { value: 'blocked_spike', label: 'Blocked Spike' },
  { value: 'new_peer', label: 'New Peer' },
]

const SEVERITIES = [
  { value: 'critical', label: 'Critical' },
  { value: 'warning', label: 'Warning' },
  { value: 'info', label: 'Info' },
]

const STATUSES = [
  { value: 'sent', label: 'Sent' },
  { value: 'pending', label: 'Pending' },
  { value: 'failed', label: 'Failed' },
]

function SeverityIcon({ severity }) {
  const config = {
    critical: { icon: AlertTriangle, color: 'text-red-500' },
    warning: { icon: AlertTriangle, color: 'text-amber-500' },
    info: { icon: Info, color: 'text-blue-500' },
  }
  const { icon: Icon, color } = config[severity] || config.info
  return <Icon className={`w-4 h-4 ${color}`} />
}

function AlertTypeTag({ alertType }) {
  const colorConfig = {
    bundle_deployed: 'border-green-500 text-green-700 dark:text-green-400',
    bundle_failed: 'border-red-500 text-red-700 dark:text-red-400',
    peer_offline: 'border-orange-500 text-orange-700 dark:text-orange-400',
    peer_online: 'border-blue-500 text-blue-700 dark:text-blue-400',
    blocked_spike: 'border-purple-500 text-purple-700 dark:text-purple-400',
    new_peer: 'border-cyan-500 text-cyan-700 dark:text-cyan-400',
  }
  const colorClasses = colorConfig[alertType] || 'border-gray-500 text-gray-700 dark:text-gray-400'
  const displayText = alertType.toUpperCase()
  
  return (
    <span className={`inline-block px-1.5 py-0.5 border font-mono text-[10px] ${colorClasses}`}>
      [{displayText}]
    </span>
  )
}

function StatusTag({ status }) {
  const colorConfig = {
    sent: 'border-green-500 text-green-700 dark:text-green-400',
    pending: 'border-amber-500 text-amber-700 dark:text-amber-400',
    failed: 'border-red-500 text-red-700 dark:text-red-400',
  }
  const colorClasses = colorConfig[status] || 'border-gray-500 text-gray-700 dark:text-gray-400'
  const displayText = status.toUpperCase()
  
  return (
    <span className={`inline-block px-1.5 py-0.5 border font-mono text-[10px] ${colorClasses}`}>
      [{displayText}]
    </span>
  )
}

function formatTimestamp(timestamp) {
  const date = new Date(timestamp)
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function AlertRow({ alert, isExpanded, onToggle, onDelete }) {
  return (
    <>
    <tr
      onClick={onToggle}
      className="cursor-pointer hover:bg-gray-50 dark:hover:bg-charcoal-darkest transition-colors"
    >
      <td className="px-4 py-1.5 text-center w-12">
        {isExpanded ? (
          <ChevronUp className="w-4 h-4 text-gray-500 dark:text-amber-muted mx-auto" />
        ) : (
          <ChevronDown className="w-4 h-4 text-gray-500 dark:text-amber-muted mx-auto" />
        )}
      </td>

      <td className="px-4 py-1.5">
        <SeverityIcon severity={alert.severity} />
      </td>

      <td className="px-4 py-1.5 text-sm text-gray-600 dark:text-amber-muted whitespace-nowrap">
        {formatTimestamp(alert.created_at)}
      </td>

      <td className="px-4 py-1.5">
        <AlertTypeTag alertType={alert.alert_type} />
      </td>

      <td className="px-4 py-1.5 text-sm text-gray-900 dark:text-light-neutral">
        {alert.peer_hostname || '-'}
      </td>

      <td className="px-4 py-1.5 text-sm text-gray-900 dark:text-light-neutral max-w-[200px] truncate">
        {alert.subject}
      </td>

      <td className="px-4 py-1.5">
        <StatusTag status={alert.status} />
      </td>
    </tr>

      {isExpanded && (
        <tr className="bg-gray-50 dark:bg-charcoal-darkest">
          <td colSpan={7} className="px-4 py-4">
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-medium text-gray-900 dark:text-light-neutral mb-1">Message</h4>
                <p className="text-sm text-gray-600 dark:text-amber-muted whitespace-pre-wrap">
                  {alert.message}
                </p>
              </div>

              {alert.metadata && (
                <div>
                  <h4 className="text-sm font-medium text-gray-900 dark:text-light-neutral mb-1">Metadata</h4>
                  <pre className="text-xs bg-gray-900 dark:bg-black text-green-400 p-3 overflow-x-auto">
                    {JSON.stringify(alert.metadata, null, 2)}
                  </pre>
                </div>
              )}

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                                                        <div>
                                                                <span className="text-gray-500 dark:text-amber-muted">Severity:</span>
                                                                <span className="ml-2 text-gray-900 dark:text-light-neutral capitalize">{alert.severity}</span>
                                                        </div>
                                                        <div>
                                                                <span className="text-gray-500 dark:text-amber-muted">Alert ID:</span>
                                                                <span className="ml-2 text-gray-900 dark:text-light-neutral">{alert.id}</span>
                                                        </div>
                                                        <div>
                                                                <span className="text-gray-500 dark:text-amber-muted">Peer:</span>
                                                                <span className="ml-2 text-gray-900 dark:text-light-neutral">{alert.peer_hostname || alert.peer_id || '-'}</span>
                                                        </div>
                                                        <div>
                                                                <span className="text-gray-500 dark:text-amber-muted">Created:</span>
                                                                <span className="ml-2 text-gray-900 dark:text-light-neutral">
                                                                        {new Date(alert.created_at).toLocaleString()}
                                                                </span>
                                                        </div>
                                                        <div>
                                                                <span className="text-gray-500 dark:text-amber-muted">Sent At:</span>
                                                                <span className="ml-2 text-gray-900 dark:text-light-neutral">
                                                                        {alert.sent_at ? new Date(alert.sent_at).toLocaleString() : '-'}
                                                                </span>
                                                        </div>
                                                </div>

              <div className="pt-2 border-t border-gray-200 dark:border-gray-border">
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    onDelete(alert.id)
                  }}
                  className="flex items-center gap-2 px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                  Delete Alert
                </button>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

function AccessDenied() {
  return (
    <div className="flex items-center justify-center min-h-[400px]">
      <div className="text-center">
        <Bell className="w-16 h-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
        <h2 className="text-xl font-semibold text-gray-900 dark:text-light-neutral mb-2">
          Access Denied
        </h2>
        <p className="text-gray-600 dark:text-amber-muted">
          You need administrator access to view the Alerts page.
        </p>
      </div>
    </div>
  )
}

export default function Alerts() {
  const { isAdmin } = useAuth()
  const qc = useQueryClient()
  const showToast = useToastContext()
  const { sortConfig, handleSort } = useTableSort('alerts', { key: 'created_at', direction: 'desc' })
  const { value: rowsPerPage, setValue: setRowsPerPage } = useFilterPersistence('alerts', 'rowsPerPage', 25)
  const [filter, setFilter] = useState({
    alert_types: [],
    severities: [],
    statuses: [],
    start_date: '',
    end_date: '',
    page: 1,
  })
  const [expandedRow, setExpandedRow] = useState(null)
  const [showDeleteModal, setShowDeleteModal] = useState(null)
  const [showClearAllModal, setShowClearAllModal] = useState(false)
  const deleteModalRef = useRef(null)
  const clearAllModalRef = useRef(null)
  useFocusTrap(deleteModalRef, showDeleteModal !== null)
  useFocusTrap(clearAllModalRef, showClearAllModal)

  const queryParams = new URLSearchParams()
  if (filter.alert_types.length > 0) queryParams.set('alert_type', filter.alert_types.join(','))
  if (filter.severities.length > 0) queryParams.set('severity', filter.severities.join(','))
  if (filter.statuses.length > 0) queryParams.set('status', filter.statuses.join(','))
  if (filter.start_date) queryParams.set('start_date', filter.start_date)
  if (filter.end_date) queryParams.set('end_date', filter.end_date)
  queryParams.set('page', String(filter.page))
  queryParams.set('limit', String(rowsPerPage === -1 ? 1000 : rowsPerPage))
  queryParams.set('sort_key', sortConfig.key)
  queryParams.set('sort_direction', sortConfig.direction)

  const filterWithSort = { ...filter, limit: rowsPerPage, sort_key: sortConfig.key, sort_direction: sortConfig.direction }

  const { data, isLoading } = useQuery({
    queryKey: QUERY_KEYS.alerts(filterWithSort),
    queryFn: () => api.get(`/alerts?${queryParams.toString()}`),
    enabled: isAdmin,
  })

  const deleteMutation = useMutation({
    mutationFn: deleteAlert,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QUERY_KEYS.alerts(filterWithSort) })
      showToast('Alert deleted', 'success')
      setShowDeleteModal(null)
      setExpandedRow(null)
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const clearAllMutation = useMutation({
    mutationFn: clearAllAlerts,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QUERY_KEYS.alerts(filterWithSort) })
      showToast('All alerts cleared', 'success')
      setShowClearAllModal(false)
      setExpandedRow(null)
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const handleClearFilters = () => {
    setFilter({
      alert_types: [],
      severities: [],
      statuses: [],
      start_date: '',
      end_date: '',
      page: 1,
    })
  }

  const handlePageChange = (newPage) => {
    setFilter(f => ({ ...f, page: newPage }))
  }

  const handleRowsPerPageChange = (newRowsPerPage) => {
    setRowsPerPage(newRowsPerPage)
    setFilter(f => ({ ...f, page: 1 }))
  }

  const toggleRow = (id) => {
    setExpandedRow(expandedRow === id ? null : id)
  }

  const handleDeleteAlert = (id) => {
    setShowDeleteModal(id)
  }

  const confirmDeleteAlert = () => {
    if (showDeleteModal) {
      deleteMutation.mutate(showDeleteModal)
    }
  }

  const confirmClearAll = () => {
    clearAllMutation.mutate()
  }

  if (!isAdmin) {
    return (
      <div className="space-y-4">
        <PageHeader
          title="Alerts"
          description="View and manage system alerts"
        />
        <AccessDenied />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Alerts"
        description="View alert history and notifications"
        actions={
          <>
            {data?.alerts?.length > 0 && (
              <button
                onClick={() => setShowClearAllModal(true)}
                className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40 transition-colors rounded-none"
              >
                <Trash2 className="w-4 h-4" /> Clear All Alerts
              </button>
            )}
          </>
        }
      />

<SearchFilterPanel
			storageKey="alerts-filters-expanded"
			showSearch={false}
			hasActiveFilters={filter.alert_types.length > 0 || filter.severities.length > 0 || filter.statuses.length > 0 || filter.start_date || filter.end_date}
			filterContent={
			<div className="flex items-center gap-4">
				<div className="space-y-1 min-w-[150px]">
					<label className="text-xs font-medium text-gray-500 dark:text-amber-muted">Alert Type</label>
					<MultiSelect
						options={ALERT_TYPES}
						values={filter.alert_types}
						onChange={(values) => setFilter(f => ({ ...f, alert_types: values, page: 1 }))}
						placeholder="All types"
					/>
				</div>

				<div className="space-y-1 min-w-[120px]">
					<label className="text-xs font-medium text-gray-500 dark:text-amber-muted">Severity</label>
					<MultiSelect
						options={SEVERITIES}
						values={filter.severities}
						onChange={(values) => setFilter(f => ({ ...f, severities: values, page: 1 }))}
						placeholder="All severities"
					/>
				</div>

				<div className="space-y-1 min-w-[120px]">
					<label className="text-xs font-medium text-gray-500 dark:text-amber-muted">Status</label>
					<MultiSelect
						options={STATUSES}
						values={filter.statuses}
						onChange={(values) => setFilter(f => ({ ...f, statuses: values, page: 1 }))}
						placeholder="All statuses"
					/>
				</div>

				<div className="space-y-1 min-w-[150px]">
					<label className="text-xs font-medium text-gray-500 dark:text-amber-muted">From Date</label>
					<div className="relative">
						<Calendar className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 dark:text-amber-muted" />
						<input
							type="date"
							value={filter.start_date}
							onChange={e => setFilter(f => ({ ...f, start_date: e.target.value, page: 1 }))}
							className="w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-border bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral text-sm focus:ring-2 focus:ring-purple-active focus:border-purple-active"
						/>
					</div>
				</div>

				<div className="space-y-1 min-w-[150px]">
					<label className="text-xs font-medium text-gray-500 dark:text-amber-muted">To Date</label>
					<div className="relative">
						<Calendar className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 dark:text-amber-muted" />
						<input
							type="date"
							value={filter.end_date}
							onChange={e => setFilter(f => ({ ...f, end_date: e.target.value, page: 1 }))}
							className="w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-border bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral text-sm focus:ring-2 focus:ring-purple-active focus:border-purple-active"
						/>
					</div>
				</div>

				<div className="space-y-1 min-w-[80px]">
					<label className="text-xs font-medium text-gray-500 dark:text-amber-muted">Rows</label>
					<select
						value={rowsPerPage}
						onChange={e => handleRowsPerPageChange(Number(e.target.value))}
						className="w-full px-2 py-2 border border-gray-300 dark:border-gray-border bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral text-sm focus:ring-2 focus:ring-purple-active focus:border-purple-active"
					>
						<option value={10}>10</option>
						<option value={25}>25</option>
						<option value={50}>50</option>
						<option value={100}>100</option>
						<option value={-1}>All</option>
					</select>
				</div>
			</div>
		}
	rightContent={
			(filter.alert_types.length > 0 || filter.severities.length > 0 || filter.statuses.length > 0 || filter.start_date || filter.end_date) ? (
				<button
					onClick={handleClearFilters}
					className="flex items-center gap-1 px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20"
				>
					<X className="w-4 h-4" />
					Clear
				</button>
			) : null
		}
      />

      {isLoading && <TableSkeleton rows={5} columns={7} />}

      {!isLoading && data && (
        <>
          {!data.alerts?.length ? (
            <EmptyState
              icon={Bell}
              title="No alerts"
              message="No alerts match your current filters."
            />
          ) : (
<div className="bg-white dark:bg-charcoal-dark border border-gray-200 dark:border-gray-border overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full">
        <thead className="bg-gray-50 dark:bg-charcoal-darkest border-b border-gray-200 dark:border-gray-border">
          <tr>
            <th className="px-4 py-1.5 w-12" aria-label="Expand/collapse"></th>
            <th className="px-4 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
              <button type="button" onClick={() => handleSort('severity')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                Sev <SortIndicator columnKey="severity" sortConfig={sortConfig} />
              </button>
            </th>
            <th className="px-4 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
              <button type="button" onClick={() => handleSort('created_at')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                Timestamp <SortIndicator columnKey="created_at" sortConfig={sortConfig} />
              </button>
            </th>
            <th className="px-4 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
              <button type="button" onClick={() => handleSort('alert_type')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                Alert Type <SortIndicator columnKey="alert_type" sortConfig={sortConfig} />
              </button>
            </th>
            <th className="px-4 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
              <button type="button" onClick={() => handleSort('peer_hostname')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                Peer <SortIndicator columnKey="peer_hostname" sortConfig={sortConfig} />
              </button>
            </th>
            <th className="px-4 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">
              Subject
            </th>
            <th className="px-4 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
              <button type="button" onClick={() => handleSort('status')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                Status <SortIndicator columnKey="status" sortConfig={sortConfig} />
              </button>
            </th>
          </tr>
        </thead>
                  <tbody className="divide-y divide-gray-200 dark:divide-gray-border">
                    {data.alerts.map((alert) => (
                      <AlertRow
                        key={alert.id}
                        alert={alert}
                        isExpanded={expandedRow === alert.id}
                        onToggle={() => toggleRow(alert.id)}
                        onDelete={handleDeleteAlert}
                      />
                    ))}
                  </tbody>
                </table>
              </div>

              <Pagination
          showingRange={rowsPerPage === -1
            ? `Showing all ${data.total}`
            : `Showing ${(filter.page - 1) * rowsPerPage + 1} - ${Math.min(filter.page * rowsPerPage, data.total)} of ${data.total}`
          }
          page={filter.page}
          totalPages={rowsPerPage === -1 ? 1 : Math.ceil(data.total / rowsPerPage)}
          onPageChange={handlePageChange}
          totalItems={data.total}
        />
            </div>
          )}
        </>
      )}

      {!isLoading && !data && (
        <EmptyState
          icon={Bell}
          title="No alerts"
          message="No alerts have been generated yet."
        />
      )}

      {showDeleteModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div ref={deleteModalRef} className="bg-white dark:bg-charcoal-dark border border-gray-200 dark:border-gray-border p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
              Delete Alert?
            </h3>
            <p className="text-gray-600 dark:text-amber-muted mb-6">
              This action cannot be undone. The alert will be permanently removed from the history.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowDeleteModal(null)}
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest rounded-none"
              >
                Cancel
              </button>
              <button
                onClick={confirmDeleteAlert}
                disabled={deleteMutation.isPending}
className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white disabled:opacity-50 rounded-none"
>
{deleteMutation.isPending ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}

      {showClearAllModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div ref={clearAllModalRef} className="bg-white dark:bg-charcoal-dark border border-gray-200 dark:border-gray-border p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
              Clear All Alerts?
            </h3>
            <p className="text-gray-600 dark:text-amber-muted mb-6">
              This will permanently delete all {data?.total?.toLocaleString() || 0} alerts. This action cannot be undone.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowClearAllModal(false)}
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest rounded-none"
              >
                Cancel
              </button>
              <button
onClick={confirmClearAll}
          disabled={clearAllMutation.isPending}
          className="flex-1 px-4 py-2 text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40 disabled:opacity-50 rounded-none font-medium transition-colors"
>
{clearAllMutation.isPending ? 'Clearing...' : 'Clear All Alerts'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
