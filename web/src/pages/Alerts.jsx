import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bell, Filter, ChevronDown, ChevronUp, Calendar, Search, X, Trash2 } from 'lucide-react'
import { api, QUERY_KEYS, deleteAlert, clearAllAlerts } from '../api/client'
import { useAuth } from '../hooks/useAuth'
import { useToastContext } from '../hooks/ToastContext'
import { useFocusTrap } from '../hooks/useFocusTrap'
import PageHeader from '../components/PageHeader'
import Pagination from '../components/Pagination'
import EmptyState from '../components/EmptyState'
import TableSkeleton from '../components/TableSkeleton'

// Alert type options
const ALERT_TYPES = [
  { value: 'bundle_deployed', label: 'Bundle Deployed' },
  { value: 'bundle_failed', label: 'Bundle Failed' },
  { value: 'peer_offline', label: 'Peer Offline' },
  { value: 'peer_online', label: 'Peer Online' },
  { value: 'blocked_spike', label: 'Blocked Spike' },
  { value: 'new_peer', label: 'New Peer' },
]

// Severity options
const SEVERITIES = [
  { value: 'critical', label: 'Critical' },
  { value: 'warning', label: 'Warning' },
  { value: 'info', label: 'Info' },
]

// Status options
const STATUSES = [
  { value: 'sent', label: 'Sent' },
  { value: 'pending', label: 'Pending' },
  { value: 'failed', label: 'Failed' },
]

// Severity badge colors
function getSeverityBadgeClass(severity) {
  switch (severity) {
    case 'critical':
      return 'bg-red-100 text-red-700 dark:bg-red-900/50 dark:text-red-300'
    case 'warning':
      return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/50 dark:text-yellow-300'
    case 'info':
      return 'bg-blue-100 text-blue-700 dark:bg-blue-900/50 dark:text-blue-300'
    default:
      return 'bg-gray-100 text-gray-700 dark:bg-gray-700/50 dark:text-gray-300'
  }
}

// Status badge colors
function getStatusBadgeClass(status) {
  switch (status) {
    case 'sent':
      return 'bg-green-100 text-green-700 dark:bg-green-900/50 dark:text-green-300'
    case 'pending':
      return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/50 dark:text-yellow-300'
    case 'failed':
      return 'bg-red-100 text-red-700 dark:bg-red-900/50 dark:text-red-300'
    default:
      return 'bg-gray-100 text-gray-700 dark:bg-gray-700/50 dark:text-gray-300'
  }
}

// Alert type badge
function getAlertTypeBadgeClass(alertType) {
  switch (alertType) {
    case 'bundle_deployed':
      return 'bg-green-100 text-green-700 dark:bg-green-900/50 dark:text-green-300'
    case 'bundle_failed':
      return 'bg-red-100 text-red-700 dark:bg-red-900/50 dark:text-red-300'
    case 'peer_offline':
      return 'bg-orange-100 text-orange-700 dark:bg-orange-900/50 dark:text-orange-300'
    case 'peer_online':
      return 'bg-blue-100 text-blue-700 dark:bg-blue-900/50 dark:text-blue-300'
    case 'blocked_spike':
      return 'bg-purple-100 text-purple-700 dark:bg-purple-900/50 dark:text-purple-300'
    case 'new_peer':
      return 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/50 dark:text-cyan-300'
    default:
      return 'bg-gray-100 text-gray-700 dark:bg-gray-700/50 dark:text-gray-300'
  }
}

// Format timestamp
function formatTimestamp(timestamp) {
  const date = new Date(timestamp)
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

// Filter bar component
function FilterBar({ filter, setFilter, onClear }) {
  const [expanded, setExpanded] = useState(false)

  const handleChange = (key, value) => {
    setFilter(f => ({ ...f, [key]: value, offset: 0 }))
  }

  const hasActiveFilters = filter.alert_type || filter.severity || filter.status || filter.start_date || filter.end_date

  return (
    <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm overflow-hidden">
      {/* Filter toggle */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between p-4 text-left hover:bg-gray-50 dark:hover:bg-charcoal-darkest transition-colors"
      >
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-500 dark:text-amber-muted" />
          <span className="font-medium text-gray-900 dark:text-light-neutral">Filters</span>
          {hasActiveFilters && (
            <span className="px-2 py-0.5 text-xs bg-purple-active text-white rounded-full">
              Active
            </span>
          )}
        </div>
        {expanded ? (
          <ChevronUp className="w-4 h-4 text-gray-500 dark:text-amber-muted" />
        ) : (
          <ChevronDown className="w-4 h-4 text-gray-500 dark:text-amber-muted" />
        )}
      </button>

      {/* Filter options */}
      {expanded && (
        <div className="p-4 pt-0 border-t border-gray-200 dark:border-gray-border">
          <div className="flex flex-wrap gap-4 items-end">
            {/* Alert Type */}
            <div className="space-y-1 min-w-[150px]">
              <label className="text-xs font-medium text-gray-500 dark:text-amber-muted">Alert Type</label>
              <select
                value={filter.alert_type}
                onChange={e => handleChange('alert_type', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white text-sm"
              >
                <option value="">All types</option>
                {ALERT_TYPES.map(t => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>

            {/* Severity */}
            <div className="space-y-1 min-w-[120px]">
              <label className="text-xs font-medium text-gray-500 dark:text-amber-muted">Severity</label>
              <select
                value={filter.severity}
                onChange={e => handleChange('severity', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white text-sm"
              >
                <option value="">All severities</option>
                {SEVERITIES.map(s => (
                  <option key={s.value} value={s.value}>{s.label}</option>
                ))}
              </select>
            </div>

            {/* Status */}
            <div className="space-y-1 min-w-[120px]">
              <label className="text-xs font-medium text-gray-500 dark:text-amber-muted">Status</label>
              <select
                value={filter.status}
                onChange={e => handleChange('status', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white text-sm"
              >
                <option value="">All statuses</option>
                {STATUSES.map(s => (
                  <option key={s.value} value={s.value}>{s.label}</option>
                ))}
              </select>
            </div>

            {/* Date Range */}
            <div className="space-y-1 min-w-[150px]">
              <label className="text-xs font-medium text-gray-500 dark:text-amber-muted">From Date</label>
              <div className="relative">
                <Calendar className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 dark:text-amber-muted" />
                <input
                  type="date"
                  value={filter.start_date}
                  onChange={e => handleChange('start_date', e.target.value)}
                  className="w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white text-sm"
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
                  onChange={e => handleChange('end_date', e.target.value)}
                  className="w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white text-sm"
                />
              </div>
            </div>

            {/* Clear filters */}
            {hasActiveFilters && (
              <button
                onClick={onClear}
                className="flex items-center gap-1 px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg"
              >
                <X className="w-4 h-4" />
                Clear
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// Alert row component
function AlertRow({ alert, isExpanded, onToggle, onDelete }) {
	const alertTypeLabel = ALERT_TYPES.find(t => t.value === alert.alert_type)?.label || alert.alert_type

	return (
		<>
			<tr
				onClick={onToggle}
				className="cursor-pointer hover:bg-gray-50 dark:hover:bg-charcoal-darkest transition-colors"
			>
	{/* Timestamp */}
			<td className="px-4 py-3 text-sm text-gray-600 dark:text-amber-muted whitespace-nowrap">
				{formatTimestamp(alert.created_at)}
			</td>

				{/* Alert Type */}
				<td className="px-4 py-3">
					<span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${getAlertTypeBadgeClass(alert.alert_type)}`}>
						{alertTypeLabel}
					</span>
				</td>

				{/* Peer */}
				<td className="px-4 py-3 text-sm text-gray-900 dark:text-light-neutral">
					{alert.peer_hostname || '-'}
				</td>

				{/* Severity */}
				<td className="px-4 py-3">
					<span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${getSeverityBadgeClass(alert.severity)}`}>
						{alert.severity}
					</span>
				</td>

				{/* Subject */}
				<td className="px-4 py-3 text-sm text-gray-900 dark:text-light-neutral max-w-[200px] truncate">
					{alert.subject}
				</td>

				{/* Status */}
				<td className="px-4 py-3">
					<span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${getStatusBadgeClass(alert.status)}`}>
						{alert.status}
					</span>
				</td>

				{/* Expand icon */}
				<td className="px-4 py-3 text-center">
					{isExpanded ? (
						<ChevronUp className="w-4 h-4 text-gray-500 dark:text-amber-muted mx-auto" />
					) : (
						<ChevronDown className="w-4 h-4 text-gray-500 dark:text-amber-muted mx-auto" />
					)}
				</td>
			</tr>

			{/* Expanded content */}
			{isExpanded && (
				<tr className="bg-gray-50 dark:bg-charcoal-darkest">
					<td colSpan={7} className="px-4 py-4">
						<div className="space-y-4">
							{/* Full message */}
							<div>
								<h4 className="text-sm font-medium text-gray-900 dark:text-light-neutral mb-1">Message</h4>
								<p className="text-sm text-gray-600 dark:text-amber-muted whitespace-pre-wrap">
									{alert.message}
								</p>
							</div>

							{/* Metadata JSON */}
							{alert.metadata && (
								<div>
									<h4 className="text-sm font-medium text-gray-900 dark:text-light-neutral mb-1">Metadata</h4>
									<pre className="text-xs bg-gray-900 dark:bg-black text-green-400 p-3 rounded-lg overflow-x-auto">
										{JSON.stringify(alert.metadata, null, 2)}
									</pre>
								</div>
							)}

							{/* Additional details */}
							<div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
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

							{/* Delete button */}
							<div className="pt-2 border-t border-gray-200 dark:border-gray-border">
								<button
									onClick={(e) => {
										e.stopPropagation()
										onDelete(alert.id)
									}}
									className="flex items-center gap-2 px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
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

// Access denied component
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
	const [filter, setFilter] = useState({
		alert_type: '',
		severity: '',
		status: '',
		start_date: '',
		end_date: '',
		page: 1,
		limit: 25,
	})
	const [expandedRow, setExpandedRow] = useState(null)
	const [showDeleteModal, setShowDeleteModal] = useState(null)
	const [showClearAllModal, setShowClearAllModal] = useState(false)
  const deleteModalRef = useRef(null)
  useFocusTrap(deleteModalRef, showDeleteModal !== null)

	// Build query params
	const queryParams = new URLSearchParams()
	if (filter.alert_type) queryParams.set('alert_type', filter.alert_type)
	if (filter.severity) queryParams.set('severity', filter.severity)
	if (filter.status) queryParams.set('status', filter.status)
	if (filter.start_date) queryParams.set('start_date', filter.start_date)
	if (filter.end_date) queryParams.set('end_date', filter.end_date)
	queryParams.set('page', String(filter.page))
	queryParams.set('limit', String(filter.limit))

	// Fetch alerts
	const { data, isLoading } = useQuery({
		queryKey: QUERY_KEYS.alerts(filter),
		queryFn: () => api.get(`/alerts?${queryParams.toString()}`),
		enabled: isAdmin,
	})

	// Delete single alert mutation
	const deleteMutation = useMutation({
		mutationFn: deleteAlert,
		onSuccess: () => {
			qc.invalidateQueries({ queryKey: QUERY_KEYS.alerts(filter) })
			showToast('Alert deleted', 'success')
			setShowDeleteModal(null)
			setExpandedRow(null)
		},
		onError: (err) => showToast(err.message, 'error'),
	})

	// Clear all alerts mutation
	const clearAllMutation = useMutation({
		mutationFn: clearAllAlerts,
		onSuccess: () => {
			qc.invalidateQueries({ queryKey: QUERY_KEYS.alerts(filter) })
			showToast('All alerts cleared', 'success')
			setShowClearAllModal(false)
			setExpandedRow(null)
		},
		onError: (err) => showToast(err.message, 'error'),
	})

	const handleClearFilters = () => {
		setFilter({
			alert_type: '',
			severity: '',
			status: '',
			start_date: '',
			end_date: '',
			page: 1,
			limit: 25,
		})
	}

	const handlePageChange = (newPage) => {
		setFilter(f => ({ ...f, page: newPage }))
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

	// Check if admin
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
			{/* Header */}
			<PageHeader
				title="Alerts"
				description="View alert history and notifications"
			/>

			{/* Filter bar */}
			<FilterBar
				filter={filter}
				setFilter={setFilter}
				onClear={handleClearFilters}
			/>

			{/* Clear All Alerts button */}
			{data?.alerts?.length > 0 && (
				<div className="flex justify-end">
					<button
						onClick={() => setShowClearAllModal(true)}
						className="flex items-center gap-2 px-4 py-2 text-sm text-red-600 dark:text-red-400 border border-red-300 dark:border-red-800 rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
					>
						<Trash2 className="w-4 h-4" />
						Clear All Alerts
					</button>
				</div>
			)}

			{/* Loading state */}
			{isLoading && <TableSkeleton rows={5} columns={7} />}

			{/* Alerts table */}
			{!isLoading && data && (
				<>
					{!data.alerts?.length ? (
						<EmptyState
							icon={Bell}
							title="No alerts"
							message="No alerts match your current filters."
						/>
					) : (
						<div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm overflow-hidden">
							<div className="overflow-x-auto">
								<table className="w-full">
									<thead className="bg-gray-50 dark:bg-charcoal-darkest border-b border-gray-200 dark:border-gray-border">
										<tr>
											<th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">
												Timestamp
											</th>
											<th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">
												Alert Type
											</th>
											<th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">
												Peer
											</th>
											<th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">
												Severity
											</th>
											<th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">
												Subject
											</th>
											<th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">
												Status
											</th>
											<th className="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider w-12">
												Details
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

							{/* Pagination */}
							<Pagination
								showingRange={`Showing ${(filter.page - 1) * filter.limit + 1} - ${Math.min(filter.page * filter.limit, data.total)} of ${data.total}`}
								page={filter.page}
								totalPages={Math.ceil(data.total / filter.limit)}
								onPageChange={handlePageChange}
								totalItems={data.total}
							/>
						</div>
					)}
				</>
			)}

			{/* No data state (before query) */}
			{!isLoading && !data && (
				<EmptyState
					icon={Bell}
					title="No alerts"
					message="No alerts have been generated yet."
				/>
			)}

			{/* Delete Alert Confirmation Modal */}
			{showDeleteModal && (
				<div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
					<div ref={deleteModalRef} className="bg-white dark:bg-charcoal-dark rounded-lg p-6 max-w-md w-full mx-4">
						<h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
							Delete Alert?
						</h3>
						<p className="text-gray-600 dark:text-amber-muted mb-6">
							This action cannot be undone. The alert will be permanently removed from the history.
						</p>
						<div className="flex gap-3">
							<button
								onClick={() => setShowDeleteModal(null)}
								className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border rounded-lg text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
							>
								Cancel
							</button>
							<button
								onClick={confirmDeleteAlert}
								disabled={deleteMutation.isPending}
								className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg disabled:opacity-50"
							>
								{deleteMutation.isPending ? 'Deleting...' : 'Delete'}
							</button>
						</div>
					</div>
				</div>
			)}

			{/* Clear All Alerts Confirmation Modal */}
			{showClearAllModal && (
				<div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
					<div className="bg-white dark:bg-charcoal-dark rounded-lg p-6 max-w-md w-full mx-4">
						<h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
							Clear All Alerts?
						</h3>
						<p className="text-gray-600 dark:text-amber-muted mb-6">
							This will permanently delete all {data?.total?.toLocaleString() || 0} alerts. This action cannot be undone.
						</p>
						<div className="flex gap-3">
							<button
								onClick={() => setShowClearAllModal(false)}
								className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border rounded-lg text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
							>
								Cancel
							</button>
							<button
								onClick={confirmClearAll}
								disabled={clearAllMutation.isPending}
								className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg disabled:opacity-50"
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