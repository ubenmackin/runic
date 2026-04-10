import { useState, useCallback, useRef, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { useTableSort } from '../hooks/useTableSort'
import { usePagination } from '../hooks/usePagination'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Pencil, Trash2, Server, Copy, Check, RefreshCw, X, FileCode, AlertTriangle, Globe, ChevronDown, ChevronUp, Send } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { REFETCH_INTERVALS } from '../constants'
import { useCrudModal } from '../hooks/useCrudModal'
import { useToastContext } from '../hooks/ToastContext'
import { formatRelativeTime } from '../utils/formatTime.js'
import { useFocusTrap } from '../hooks/useFocusTrap'
import { useTableFilter } from '../hooks/useTableFilter'
import { useFilterPersistence } from '../hooks/useFilterPersistence'
import { useCrudMutations } from '../hooks/useCrudMutations'
import { useAuth } from '../hooks/useAuth'
import ConfirmModal from '../components/ConfirmModal'
import SearchableSelect from '../components/SearchableSelect'
import InlineError from '../components/InlineError'
import EmptyState from '../components/EmptyState'
import TableSkeleton from '../components/TableSkeleton'
import SortIndicator from '../components/SortIndicator'
import Pagination from '../components/Pagination'
import TableToolbar from '../components/TableToolbar'
import PageHeader from '../components/PageHeader'
import PendingChangesModal from '../components/PendingChangesModal'

const OS_OPTIONS = [
  { value: 'ubuntu', label: 'Ubuntu' },
  { value: 'opensuse', label: 'openSUSE' },
  { value: 'raspbian', label: 'Raspbian' },
  { value: 'armbian', label: 'Armbian' },
  { value: 'ios', label: 'iOS' },
  { value: 'ipados', label: 'iPadOS' },
  { value: 'macos', label: 'macOS' },
  { value: 'tvos', label: 'tvOS' },
  { value: 'windows', label: 'Windows' },
  { value: 'linux', label: 'Generic Linux' },
  { value: 'other', label: 'Other' },
]

const ARCH_OPTIONS = [
  { value: 'amd64', label: 'amd64' },
  { value: 'arm64', label: 'arm64' },
  { value: 'arm', label: 'arm' },
  { value: 'other', label: 'Other' },
]

// Helper function to parse heartbeat for sorting
function parseHeartbeatForSort(timestamp) {
  if (!timestamp) return 0
  return new Date(timestamp).getTime()
}

export default function Peers() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const { canEdit } = useAuth()
  const location = useLocation()
  const { modalOpen, setModalOpen, editItem: editPeer, setEditItem: setEditPeer, form: formData, setForm: setFormData, setFormForEdit, handleOpenAdd, handleCancel: closeModal } = useCrudModal({ hostname: '', ip_address: '', os_type: 'ubuntu', arch: 'amd64', has_docker: false, description: '' })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [conflictError, setConflictError] = useState(null)
  const [formErrors, setFormErrors] = useState({})
  const [showNetworkAddresses, setShowNetworkAddresses] = useState(false)

  // Add Peer modal state
  const [addModalOpen, setAddModalOpen] = useState(false)
  const [activeTab, setActiveTab] = useState('agent') // 'agent' or 'manual'
  const [manualForm, setManualForm] = useState({ hostname: '', ip_address: '', os_type: 'other', arch: 'other' })
  const [manualErrors, setManualErrors] = useState({})
  const [copied, setCopied] = useState(false)
  const [selectedToken, setSelectedToken] = useState('')
  const [isGenerating, setIsGenerating] = useState(false)
  const [tokenDescription, setTokenDescription] = useState('')

	// Rule Bundle state
	const [bundleModalOpen, setBundleModalOpen] = useState(false)
	const [bundleLoading, setBundleLoading] = useState(false)
	const [bundleContent, setBundleContent] = useState('')
	const [bundlePeer, setBundlePeer] = useState(null)
	const [bundleData, setBundleData] = useState(null)

	// Pending Changes Modal state
	const [pendingModalPeer, setPendingModalPeer] = useState(null)
	const [pendingModalOpen, setPendingModalOpen] = useState(false)

	// Bulk Apply All state
	const [applyAllLoading, setApplyAllLoading] = useState(false)
	const [rollbackLoading, setRollbackLoading] = useState(false)

	// Push to peer state
	const [pushTargetPeer, setPushTargetPeer] = useState(null)
	const [pushLoading, setPushLoading] = useState(false)

	const fetchBundle = async (peer) => {
		setBundlePeer(peer)
		setBundleModalOpen(true)
		setBundleLoading(true)
		setBundleContent('')
		setBundleData(null)
		try {
			const data = await api.get(`/peers/${peer.id}/bundle`)
			setBundleContent(data.content)
			setBundleData(data)
		} catch (err) {
			setBundleContent(`# Error: ${err.message}`)
			setBundleData(null)
		} finally {
			setBundleLoading(false)
		}
	}

  // Modal ref for focus trap
  const editModalRef = useRef(null)
  const addModalRef = useRef(null)
  const bundleModalRef = useRef(null)

  // Focus traps for modals
  useFocusTrap(editModalRef, modalOpen)
  useFocusTrap(addModalRef, addModalOpen)
  useFocusTrap(bundleModalRef, bundleModalOpen)

  // Sorting state (persisted per-user)
  const { sortConfig, handleSort } = useTableSort('peers', { key: 'hostname', direction: 'asc' })

  // Status filter state (persisted per-user)
  const { value: statusFilter, setValue: setStatusFilter } = useFilterPersistence('peers', 'status', 'all')

  // Manual refresh state
  const [isManualRefreshing, setIsManualRefreshing] = useState(false)

  const openAdd = () => { setFormErrors({}); handleOpenAdd() }
  const openEdit = (s) => { setEditPeer(s); setFormForEdit(s); setFormErrors({}); setModalOpen(true) }

  const openAddModal = useCallback(() => {
    setAddModalOpen(true)
    setActiveTab('agent')
    setManualForm({ hostname: '', ip_address: '', os_type: 'other', arch: 'other' })
    setManualErrors({})
    setCopied(false)
    setSelectedToken('')
    setIsGenerating(false)
    setTokenDescription('')
  }, [])

  const closeAddModal = () => {
    setAddModalOpen(false)
    setManualForm({ hostname: '', ip_address: '', os_type: 'other', arch: 'other' })
    setManualErrors({})
    setCopied(false)
  }

  // Generate agent install command
  const controlPlaneUrl = window.location.origin
  const agentInstallCommand = selectedToken
    ? `curl -sL https://raw.githubusercontent.com/ubenmackin/runic/main/scripts/install-agent.sh | sudo bash -s -- ${controlPlaneUrl} ${selectedToken}`
    : `# Select or generate a registration token first`

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(agentInstallCommand)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      showToast('Failed to copy to clipboard', 'error')
    }
  }

// NOTE: Using direct api.post instead of useMutation for simplicity.
// This is a conscious choice — the token generation is a one-off action
// within the Add Peer modal, not a shared mutation pattern.
  const handleGenerateToken = async () => {
    setIsGenerating(true)
    try {
      const data = await api.post('/registration-tokens', { description: tokenDescription || undefined })
      const fullToken = data.full_token || data.token
      setSelectedToken(fullToken)
      showToast('Registration token generated', 'success')
      qc.invalidateQueries({ queryKey: ['registration-tokens'] })
    } catch (err) {
      showToast(`Failed to generate token: ${err.message}`, 'error')
    } finally {
      setIsGenerating(false)
    }
  }

  const validateManualForm = () => {
    const errors = {}
    if (!manualForm.hostname.trim()) {
      errors.hostname = 'Name is required'
    }
    if (!manualForm.ip_address.trim()) {
      errors.ip_address = 'IP Address or CIDR is required'
    } else {
      // Basic format check - IP or CIDR
      const ipOrCidr = manualForm.ip_address.trim()
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/
      if (!ipRegex.test(ipOrCidr)) {
        errors.ip_address = 'Invalid IP address or CIDR format (e.g., 192.168.1.50 or 10.0.0.0/8)'
      }
    }
    if (!manualForm.os_type) {
      errors.os_type = 'Operating System is required'
    }
    setManualErrors(errors)
    return Object.keys(errors).length === 0
  }

  const handleManualSubmit = async (e) => {
    e.preventDefault()
    if (!validateManualForm()) return

    try {
      await api.post('/peers', {
        hostname: manualForm.hostname.trim(),
        ip_address: manualForm.ip_address.trim(),
        os_type: manualForm.os_type || null,
        arch: manualForm.arch || null,
        is_manual: true
      })
      showToast('Manual peer added successfully', 'success')
      qc.invalidateQueries({ queryKey: QUERY_KEYS.peers() })
      qc.invalidateQueries({ queryKey: ['pending-changes'] })
      closeAddModal()
    } catch (err) {
      setManualErrors({ _general: err.message })
    }
  }

  const { data: peers, isLoading, refetch } = useQuery({
    queryKey: QUERY_KEYS.peers(),
    queryFn: () => api.get('/peers'),
    refetchInterval: REFETCH_INTERVALS.PEERS_PAGE,
    refetchIntervalInBackground: false,
    refetchOnReconnect: true,
    refetchOnWindowFocus: true,
    staleTime: 15000,
  })

  const { data: registrationTokens, isLoading: tokensLoading } = useQuery({
    queryKey: ['registration-tokens'],
    queryFn: () => api.get('/registration-tokens'),
    enabled: addModalOpen,
  })

  const { data: specialTargets } = useQuery({
    queryKey: ['special-targets'],
    queryFn: () => api.get('/policies/special-targets'),
  })

  // Manual refresh handler
  const handleManualRefresh = useCallback(async () => {
    setIsManualRefreshing(true)
    await refetch()
    setIsManualRefreshing(false)
  }, [refetch])

  // Search state
  const [searchTerm, setSearchTerm] = useState('')

// Pre-filter by status filter before search/sort
const preFilteredPeers = peers?.filter(peer => {
  if (statusFilter === 'all') return true
  switch (statusFilter) {
    case 'online':
      return peer.status === 'online' && !peer.is_manual
    case 'offline':
      return peer.status === 'offline' && !peer.is_manual
    case 'manual':
      return peer.is_manual === true
    case 'agent':
      return !peer.is_manual
    case 'pending':
      return peer.pending_changes_count > 0
    default:
      return true
  }
})

  // Filtered and sorted data (includes status filter)
  const processedPeers = useTableFilter(preFilteredPeers, searchTerm, sortConfig, {
    filterFn: (peer, term) => {
      const hostname = (peer.hostname || '').toLowerCase()
      const ip = (peer.ip_address || '').toLowerCase()
      const os = (peer.os_type || peer.os || '').toLowerCase()
      const groups = (peer.groups || '').toLowerCase()
      const agent = peer.is_manual ? 'manual' : (peer.agent_version || '').toLowerCase()
      return hostname.includes(term) || ip.includes(term) || os.includes(term) || groups.includes(term) || agent.includes(term)
    },
    fieldMap: {
      os_type: (p) => (p.os_type || p.os || '').toLowerCase(),
      last_heartbeat: (p) => parseHeartbeatForSort(p.last_heartbeat),
    },
    secondarySortKey: 'hostname',
  })

  // Pagination state
  const {
    paginatedData: paginatedPeers,
    totalPages,
    showingRange: peersShowingRange,
    page: peersPage,
    rowsPerPage: peersRowsPerPage,
    onPageChange: setPeersPage,
    onRowsPerPageChange: setPeersRowsPerPage,
    totalItems: peersTotal
  } = usePagination(processedPeers, 'peers')

  // Reset page to 1 when search term changes
  useEffect(() => {
    setPeersPage(1)
  }, [searchTerm])

  // Auto-open Add Peer modal when navigating from Dashboard Quick Actions
  useEffect(() => {
    if (location.state?.openAddModal && canEdit) {
      openAddModal()
      // Clear the navigation state to prevent re-opening on refresh
      window.history.replaceState({}, document.title)
    }
  }, [location.state, canEdit, openAddModal])

const { createMutation, updateMutation, deleteMutation } = useCrudMutations({
  apiPath: '/peers',
  queryKey: QUERY_KEYS.peers(),
  additionalInvalidations: [['pending-changes']],
  onCreateSuccess: closeModal,
  onUpdateSuccess: closeModal,
  onDeleteSuccess: () => { setDeleteTarget(null); showToast('Peer deleted successfully', 'success') },
  setFormErrors,
  showToast,
})

// Custom delete handler to check for 409 Conflict errors
const handleDeleteConfirm = async () => {
  try {
    await deleteMutation.mutateAsync(deleteTarget.id)
  } catch (err) {
    // Check if it's a 409 Conflict error with policy list
    if (err.status === 409 && err.data?.policies) {
      setConflictError({
        peerName: deleteTarget.hostname,
        policies: err.data.policies,
      })
      setDeleteTarget(null)
    }
    // Other errors are already handled by the mutation's onError
  }
}

const handleSubmit = (e) => {
		e.preventDefault()
		if (editPeer) updateMutation.mutate({ id: editPeer.id, data: formData })
		else createMutation.mutate(formData)
	}

	// Calculate peers with pending changes
	const peersWithPendingChanges = peers?.filter(p => p.pending_changes_count > 0).length || 0

  const handleApplyAll = async () => {
    setApplyAllLoading(true)
    try {
      await api.post('/pending-changes/apply-all')
      showToast('All pending changes applied successfully', 'success')
      qc.invalidateQueries({ queryKey: QUERY_KEYS.peers() })
      qc.invalidateQueries({ queryKey: ['pending-changes'] })
			qc.invalidateQueries({ queryKey: QUERY_KEYS.groups() })
			qc.invalidateQueries({ queryKey: QUERY_KEYS.services() })
			qc.invalidateQueries({ queryKey: QUERY_KEYS.policies() })
    } catch (err) {
      showToast(`Failed to apply all changes: ${err.message}`, 'error')
    } finally {
      setApplyAllLoading(false)
    }
  }

  // Handle Rollback All Pending
  const handleRollback = async () => {
    if (!window.confirm('Are you sure you want to discard all pending changes? This action cannot be undone.')) return
    setRollbackLoading(true)
    try {
      await api.post('/pending-changes/rollback')
      showToast('Pending changes discarded successfully', 'success')
      qc.invalidateQueries({ queryKey: QUERY_KEYS.peers() })
      qc.invalidateQueries({ queryKey: ['pending-changes'] })
      qc.invalidateQueries({ queryKey: QUERY_KEYS.groups() })
      qc.invalidateQueries({ queryKey: QUERY_KEYS.services() })
      qc.invalidateQueries({ queryKey: QUERY_KEYS.policies() })
    } catch (err) {
      showToast(`Failed to rollback changes: ${err.message}`, 'error')
    } finally {
      setRollbackLoading(false)
    }
  }

  // Handle Sync Status badge click
  const handleSyncStatusClick = (peer) => {
    if (peer.sync_status === 'pending') {
      // Open Pending Changes modal
      setPendingModalPeer(peer)
      setPendingModalOpen(true)
    } else if (peer.sync_status === 'pending_sync' || peer.sync_status === 'synced') {
      // Open Deployed Rules modal (fetchBundle)
      fetchBundle(peer)
    }
  }

  // Handle Push to Peer
	const handlePushToPeer = async (peer) => {
		setPushTargetPeer(peer)
	}

	const handlePushConfirm = async () => {
		if (!pushTargetPeer) return
		setPushLoading(true)
		try {
			await api.post(`/pending-changes/push/${pushTargetPeer.id}`)
			showToast(`Successfully pushed current rules to ${pushTargetPeer.hostname}`, 'success')
			qc.invalidateQueries({ queryKey: QUERY_KEYS.peers() })
			qc.invalidateQueries({ queryKey: ['pending-changes'] })
			setPushTargetPeer(null)
		} catch (err) {
			showToast(`Failed to push rules: ${err.message}`, 'error')
		} finally {
			setPushLoading(false)
		}
	}

	if (isLoading) return <TableSkeleton rows={3} columns={6} />

  return (
    <div className="space-y-4">
      <PageHeader
        title="Peers"
        description="Register and manage devices and endpoints in your network"
	actions={
	<>
	{canEdit && peersWithPendingChanges > 0 && (
	<>
	<button
	onClick={handleApplyAll}
	disabled={applyAllLoading || rollbackLoading}
	className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-white bg-green-600 hover:bg-green-700 rounded-lg disabled:opacity-50"
	>
	{applyAllLoading ? (
	<>
	<RefreshCw className="w-4 h-4 animate-spin" />
	Applying...
	</>
	) : (
	<>
	Apply All ({peersWithPendingChanges})
	</>
	)}
	</button>
	<button
	onClick={handleRollback}
	disabled={applyAllLoading || rollbackLoading}
	className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40 rounded-lg disabled:opacity-50 transition-colors"
	>
	{rollbackLoading ? (
	<>
	<RefreshCw className="w-4 h-4 animate-spin" />
	Discarding...
	</>
	) : (
	<>
	<Trash2 className="w-4 h-4" />
	Discard ({peersWithPendingChanges})
	</>
	)}
	</button>
	</>
	)}
	<button
	onClick={handleManualRefresh}
	disabled={isManualRefreshing}
	className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-lg hover:bg-gray-50 dark:hover:bg-charcoal-darkest disabled:opacity-50"
	>
	<RefreshCw className={`w-4 h-4 ${isManualRefreshing ? 'animate-spin' : ''}`} />
	Refresh
	</button>
	{canEdit && (
	<button onClick={openAddModal} className="flex items-center gap-2 px-4 py-2 bg-purple-active hover:bg-purple-active/80 text-white text-sm font-medium rounded-lg">
	<Plus className="w-4 h-4" /> New Peer
	</button>
	)}
	</>
	}
      />

      {/* Network Addresses Collapsible Panel */}
      {specialTargets && specialTargets.length > 0 && (
        <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm overflow-hidden">
          <button
            type="button"
            onClick={() => setShowNetworkAddresses(!showNetworkAddresses)}
            className="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-gray-50 dark:hover:bg-charcoal-darkest transition-colors"
          >
            <div className="flex items-center gap-2">
              <Globe className="w-5 h-5 text-blue-500" />
              <span className="font-medium text-gray-900 dark:text-light-neutral">Network Addresses</span>
              <span className="text-xs text-gray-500 dark:text-amber-muted">(Special policy targets)</span>
            </div>
            {showNetworkAddresses ? (
              <ChevronUp className="w-5 h-5 text-gray-500" />
            ) : (
              <ChevronDown className="w-5 h-5 text-gray-500" />
            )}
          </button>
          {showNetworkAddresses && (
            <div className="px-4 pb-4 border-t border-gray-200 dark:border-gray-border">
              <div className="mt-3 space-y-2 text-sm">
                {specialTargets.map((target) => (
                  <div key={target.id} className="p-2 border-b border-gray-100 dark:border-gray-border last:border-b-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-gray-900 dark:text-light-neutral">{target.display_name}</span>
                      <span className="text-xs px-1.5 py-0.5 rounded bg-gray-100 dark:bg-charcoal-darkest text-gray-600 dark:text-amber-muted font-mono">
                        {target.address}
                      </span>
                    </div>
                    <p className="text-xs text-gray-600 dark:text-amber-muted mt-1">{target.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Search Bar and Rows per page */}
      <TableToolbar
        searchTerm={searchTerm}
        onSearchChange={(v) => setSearchTerm(v)}
        onClearSearch={() => setSearchTerm('')}
        placeholder="Search peers by hostname, IP, OS, groups, or agent..."
        rowsPerPage={peersRowsPerPage}
        onRowsPerPageChange={setPeersRowsPerPage}
      />

      {/* Status Filter Button Bar */}
      <div className="flex gap-2">
        {[
          { value: 'all', label: 'All' },
          { value: 'online', label: 'Online' },
          { value: 'offline', label: 'Offline' },
          { value: 'manual', label: 'Manual' },
          { value: 'agent', label: 'Agent' },
          { value: 'pending', label: 'Pending Changes' },
        ].map(opt => (
          <button
            key={opt.value}
            onClick={() => setStatusFilter(opt.value)}
            className={`px-3 py-1.5 text-sm font-medium rounded-lg transition-colors ${
              statusFilter === opt.value
                ? 'bg-purple-active text-white'
                : 'bg-gray-100 dark:bg-charcoal-darkest text-gray-700 dark:text-amber-primary hover:bg-gray-200 dark:hover:bg-charcoal-dark'
            }`}
          >
            {opt.label}
          </button>
        ))}
      </div>

      {!processedPeers?.length ? (
        searchTerm || statusFilter !== 'all' ? (
          <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm p-8 text-center">
            <p className="text-gray-500 dark:text-amber-muted">No peers match your filters.</p>
          </div>
        ) : (
          <EmptyState icon={Server} title="No peers yet" message="Add your first peer to start managing firewall rules." action="Add Peer" onAction={openAddModal} />
        )
      ) : (
        <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 dark:bg-charcoal-darkest">
                <tr>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
            <button type="button" onClick={() => handleSort('hostname')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
              Hostname <SortIndicator columnKey="hostname" sortConfig={sortConfig} />
            </button>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
            <button type="button" onClick={() => handleSort('ip_address')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
              IP Address <SortIndicator columnKey="ip_address" sortConfig={sortConfig} />
            </button>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
            <button type="button" onClick={() => handleSort('os_type')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
              OS <SortIndicator columnKey="os_type" sortConfig={sortConfig} />
            </button>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
            <button type="button" onClick={() => handleSort('last_heartbeat')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
              Last Heartbeat <SortIndicator columnKey="last_heartbeat" sortConfig={sortConfig} />
            </button>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted">
                    Groups
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted">
                    Agent
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-border">
                {paginatedPeers.map((peer) => (
                  <tr key={peer.id} className="">
<td className="px-4 py-3">
	<div className="flex items-center gap-2">
	{!peer.is_manual && (
	<span className={`w-2 h-2 rounded-full ${peer.status === 'online' ? 'bg-green-500' :
	peer.status === 'offline' ? 'bg-red-500' :
	'bg-amber-500' // pending
	}`} />
	)}
                <span className="font-medium text-gray-900 dark:text-light-neutral">{peer.hostname}</span>
                {peer.sync_status && (
                  <button
                    onClick={() => handleSyncStatusClick(peer)}
                    title={`Click to ${peer.sync_status === 'pending' ? 'review pending changes' : 'view deployed rules'}`}
                    className={`px-2 py-0.5 text-xs font-medium rounded-full cursor-pointer ${
                      peer.sync_status === 'pending'
                        ? 'bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-300 hover:bg-orange-200 dark:hover:bg-orange-900/50'
                        : peer.sync_status === 'pending_sync'
                        ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 hover:bg-blue-200 dark:hover:bg-blue-900/50'
                        : peer.sync_status === 'synced'
                        ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300 hover:bg-green-200 dark:hover:bg-green-900/50'
                        : 'bg-gray-100 dark:bg-gray-900/30 text-gray-800 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-900/50'
                    }`}
                  >
                    {peer.sync_status === 'pending'
                      ? 'Pending'
                      : peer.sync_status === 'pending_sync'
                      ? 'Pending Sync'
                      : peer.sync_status === 'synced'
                      ? 'Synced'
                      : peer.sync_status}
                  </button>
                )}
	</div>
</td>
                    <td className="px-4 py-3 text-gray-600 dark:text-amber-primary">
                      {peer.ip_address}
                    </td>
                    <td className="px-4 py-3 text-gray-600 dark:text-amber-primary">
                      {peer.os_type || peer.os || '—'}
                    </td>
                    <td className="px-4 py-3 text-gray-600 dark:text-amber-primary">
                      {peer.is_manual ? 'N/A' : formatRelativeTime(peer.last_heartbeat)}
                    </td>
                    <td className="px-4 py-3">
                      {peer.groups ? (
                        <div className="flex flex-wrap items-center gap-1.5 max-w-xs">
                          {(() => {
                            const groups = peer.groups.split(',').map(g => g.trim()).filter(Boolean)
                            const maxVisible = 2
                            const visibleGroups = groups.slice(0, maxVisible)
                            const remainingCount = groups.length - maxVisible

                            return (
                              <>
                                {visibleGroups.map((group, idx) => (
                                  <span
                                    key={idx}
                                    className="px-2 py-0.5 text-xs font-medium rounded-full bg-purple-active/20 dark:bg-purple-active text-white whitespace-nowrap"
                                  >
                                    {group}
                                  </span>
                                ))}
                                {remainingCount > 0 && (
                                  <span
                                    className="px-2 py-0.5 text-xs font-medium rounded-full bg-gray-100 dark:bg-charcoal-darkest text-gray-600 dark:text-amber-muted whitespace-nowrap"
                                    title={groups.slice(maxVisible).join(', ')}
                                  >
                                    +{remainingCount}
                                  </span>
                                )}
                              </>
                            )
                          })()}
                        </div>
                      ) : (
                        <span className="text-gray-400">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {peer.is_manual ? (
                        <span className="px-2 py-1 text-xs font-medium rounded-full bg-gray-100 dark:bg-charcoal-darkest text-gray-700 dark:text-amber-primary">
                          Manual
                        </span>
                      ) : peer.agent_version ? (
                        <span className="text-gray-600 dark:text-amber-primary">
                          v{peer.agent_version}
                        </span>
                      ) : (
                        <span className="text-gray-400 dark:text-amber-muted">—</span>
                      )}
                    </td>
                      <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {!peer.is_manual && (
                          <>
                            <button
                              onClick={() => fetchBundle(peer)}
                              className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded"
                              title="View Deployed Rules"
                            >
                              <FileCode className="w-4 h-4 text-purple-active" />
                            </button>
                            <button
                              onClick={() => handlePushToPeer(peer)}
                              className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded"
                              title="Push Current Rules"
                            >
                              <Send className="w-4 h-4 text-green-600" />
                            </button>
                          </>
                        )}
                        {canEdit && peer.is_manual && (
                          <button
                            onClick={() => openEdit(peer)}
                            className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded"
                            title="Edit"
                          >
                            <Pencil className="w-4 h-4 text-gray-900 dark:text-white" />
                          </button>
                        )}
                        {canEdit && (
                          <button
                            onClick={() => setDeleteTarget(peer)}
                            className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded"
                            title="Delete"
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

          <Pagination showingRange={peersShowingRange} page={peersPage} totalPages={totalPages} onPageChange={setPeersPage} totalItems={peersTotal} />
        </div>
      )}

      {/* Add/Edit Modal (Legacy) */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" tabIndex="-1" onKeyDown={(e) => { if (e.key === 'Escape') { closeModal() } }}>
          <div ref={editModalRef} className="bg-white dark:bg-charcoal-dark rounded-xl shadow-xl w-full max-w-lg mx-4">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border flex items-center justify-between">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">{editPeer ? 'Edit Peer' : 'Add Peer'}</h3>
              <button onClick={closeModal} className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded">
                <X className="w-5 h-5 text-gray-500" />
              </button>
            </div>
            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Hostname</label>
                <input type="text" value={formData.hostname} onChange={e => setFormData(d => ({ ...d, hostname: e.target.value }))} required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">IP Address</label>
                <input type="text" value={formData.ip_address} onChange={e => setFormData(d => ({ ...d, ip_address: e.target.value }))} required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral" />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">OS</label>
                  <SearchableSelect options={OS_OPTIONS} value={formData.os_type} onChange={v => setFormData(d => ({ ...d, os_type: v }))} />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Arch</label>
                  <SearchableSelect options={ARCH_OPTIONS} value={formData.arch} onChange={v => setFormData(d => ({ ...d, arch: v }))} />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Description</label>
                <textarea value={formData.description} onChange={e => setFormData(d => ({ ...d, description: e.target.value }))} rows={2} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral" />
              </div>
              <div className="flex items-center gap-2">
                <input type="checkbox" id="has_docker" checked={formData.has_docker} onChange={e => setFormData(d => ({ ...d, has_docker: e.target.checked }))} className="w-4 h-4 rounded border-gray-300" />
                <label htmlFor="has_docker" className="text-sm text-gray-700 dark:text-amber-primary">Has Docker</label>
              </div>
              <InlineError message={formErrors._general} />
              <div className="flex justify-end gap-3 pt-2">
                <button type="button" onClick={closeModal} className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-lg hover:bg-gray-50 dark:hover:bg-charcoal-darkest">Cancel</button>
                <button type="submit" className="px-4 py-2 text-sm font-medium text-white bg-purple-active hover:bg-purple-active/80 rounded-lg">{editPeer ? 'Save Changes' : 'Add Peer'}</button>
              </div>
            </form>
          </div>
        </div>
      )}

{deleteTarget && (
  <ConfirmModal
    title="Delete Peer"
    message={`Delete peer "${deleteTarget.hostname}"? This will also remove all rule bundles.`}
    onConfirm={handleDeleteConfirm}
    onCancel={() => setDeleteTarget(null)}
    danger
  />
)}

{/* Push to Peer Confirmation Modal */}
{pushTargetPeer && (
  <ConfirmModal
    title="Push Current Rules"
    message={`Are you sure you want to push current rules to "${pushTargetPeer.hostname}"? This will deploy all pending changes to this peer.`}
    onConfirm={handlePushConfirm}
    onCancel={() => setPushTargetPeer(null)}
    confirmText="Push"
    loading={pushLoading}
  />
)}

{/* Conflict Error Modal */}
{conflictError && (
  <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
    <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-xl w-full max-w-md mx-4">
      <div className="p-6">
        <div className="flex items-center gap-3 mb-4">
          <AlertTriangle className="w-6 h-6 text-amber-500" />
          <h3 className="text-lg font-semibold">Cannot Delete Peer</h3>
        </div>
        <p className="text-gray-600 dark:text-gray-400 mb-4">
          The peer "{conflictError.peerName}" is used by the following policies:
        </p>
        <ul className="list-disc list-inside mb-4 text-gray-700 dark:text-gray-300">
          {conflictError.policies.map(p => (
            <li key={p.id}>{p.name}</li>
          ))}
        </ul>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
          Remove this peer from those policies before deleting it.
        </p>
        <button
          onClick={() => setConflictError(null)}
          className="w-full px-4 py-2 bg-gray-100 dark:bg-charcoal-darkest rounded-lg"
        >
          Got it
        </button>
      </div>
    </div>
  </div>
)}

{/* Rule Bundle Modal */}
      {bundleModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" tabIndex="-1" onKeyDown={(e) => { if (e.key === 'Escape') { setBundleModalOpen(false) } }}>
          <div ref={bundleModalRef} className="bg-white dark:bg-charcoal-dark rounded-xl shadow-xl w-full max-w-4xl mx-4 max-h-[90vh] flex flex-col">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border flex items-center justify-between shrink-0">
              <div className="flex items-center gap-2">
                <FileCode className="w-5 h-5 text-purple-active" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">Deployed Rules: {bundlePeer?.hostname}</h3>
              </div>
              <button 
                onClick={() => setBundleModalOpen(false)} 
                className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded"
              >
                <X className="w-5 h-5 text-gray-500" />
              </button>
            </div>
            <div className="p-6 overflow-y-auto flex-1">
              {bundleLoading ? (
                <div className="flex flex-col items-center justify-center py-12 space-y-4">
                  <RefreshCw className="w-8 h-8 text-purple-active animate-spin" />
                  <p className="text-sm text-gray-500 dark:text-amber-muted">Fetching latest bundle...</p>
                </div>
	) : (
	<>
	<div className="mb-3">
	<div className="mt-2 text-sm">
	<span className="text-gray-500 dark:text-amber-muted">Bundle Version: </span>
	<span className="font-mono font-medium text-gray-900 dark:text-light-neutral" title={bundleData?.version || ''}>
	  v{bundleData?.version_number || '—'}
	</span>
	{bundleData?.is_different && (
	<span className="ml-2 px-2 py-0.5 text-xs rounded-full bg-amber-100 dark:bg-amber-900/30 text-amber-800 dark:text-amber-300">
	Pending Update
	</span>
	)}
	</div>
	</div>
	<div className="relative group">
	<pre className="bg-gray-900 dark:bg-black text-gray-100 p-6 rounded-lg text-sm font-mono overflow-auto whitespace-pre min-h-[200px] border border-gray-800">
	<code className="text-green-400">{bundleContent}</code>
	</pre>
	{bundleContent && (
	<button
	onClick={() => {
	navigator.clipboard.writeText(bundleContent)
	showToast('Copied to clipboard', 'success')
	}}
	className="absolute top-4 right-4 p-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-gray-300 transition-colors"
	title="Copy Rules"
	>
	<Copy className="w-4 h-4" />
	</button>
	)}
	</div>
	</>
	)}
            </div>
            <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-border flex justify-end shrink-0">
              <button 
                onClick={() => setBundleModalOpen(false)} 
                className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-light-neutral bg-gray-100 dark:bg-charcoal-darkest rounded-lg hover:bg-gray-200 dark:hover:bg-charcoal-dark transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Peer Modal with Tabs */}
      {addModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" tabIndex="-1" onKeyDown={(e) => { if (e.key === 'Escape') { closeAddModal() } }}>
          <div ref={addModalRef} className="bg-white dark:bg-charcoal-dark rounded-xl shadow-xl w-full max-w-lg mx-4">
            {/* Header */}
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border flex items-center justify-between">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">Add Peer</h3>
              <button
                onClick={closeAddModal}
                className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded"
              >
                <X className="w-5 h-5 text-gray-500" />
              </button>
            </div>

            {/* Tab Navigation */}
            <div className="flex border-b border-gray-200 dark:border-gray-border">
              <button
                onClick={() => setActiveTab('agent')}
                className={`flex-1 px-4 py-3 text-sm font-medium text-center border-b-2 transition-colors ${activeTab === 'agent'
                    ? 'border-purple-active text-purple-active dark:text-purple-active'
                    : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-amber-muted dark:hover:text-amber-primary'
                  }`}
              >
                Agent Install
              </button>
              <button
                onClick={() => setActiveTab('manual')}
                className={`flex-1 px-4 py-3 text-sm font-medium text-center border-b-2 transition-colors ${activeTab === 'manual'
                    ? 'border-purple-active text-purple-active dark:text-purple-active'
                    : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-amber-muted dark:hover:text-amber-primary'
                  }`}
              >
                Manual Entry
              </button>
            </div>

            {/* Tab Content */}
            <div className="p-6">
              {activeTab === 'agent' && (
      <div className="space-y-6">
            {/* Token Selection / Generation */}
                  {tokensLoading && !selectedToken ? (
                    <div className="flex items-center justify-center py-4">
                      <RefreshCw className="w-4 h-4 animate-spin text-purple-active mr-2" />
                      <span className="text-sm text-gray-500 dark:text-amber-muted">Loading tokens...</span>
                    </div>
                  ) : !selectedToken ? (
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                          Registration Token
                        </label>
                        <p className="text-xs text-gray-500 dark:text-amber-muted mb-2">
                          A single-use token is required for new agent registration.
                        </p>

                                                                {/* Token selection dropdown */}
                                                                {registrationTokens && registrationTokens.filter(t => !t.used_at && !t.is_revoked).length > 0 && (
                                                                        <div className="mb-3">
                                                                                <label className="block text-xs text-gray-600 dark:text-amber-muted mb-1">
                                                                                        Or select an existing active token:
                                                                                </label>
                                                                                <SearchableSelect
                                                                                        options={registrationTokens
                                                                                                .filter(t => !t.used_at && !t.is_revoked)
                                                                                                .map(t => ({
                                                                                                        value: t.token,
                                                                                                        label: t.description || t.token
                                                                                                }))}
                                                                                        value=""
                                                                                        onChange={(tokenValue) => setSelectedToken(tokenValue)}
                                                                                        placeholder="Select an existing token..."
                                                                                />
                                                                                <p className="text-xs text-gray-400 dark:text-amber-muted mt-1 italic">
                                                                                        Note: Only the full token value can be used in install commands. Generate a new token if you don't have the full value.
                                                                                </p>
                                                                        </div>
                                                                )}

                        {/* Token description input */}
                        <input
                          type="text"
                          value={tokenDescription}
                          onChange={(e) => setTokenDescription(e.target.value)}
                          placeholder="Description (optional, e.g., Production server #3)"
                          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral placeholder-gray-400 dark:placeholder-amber-muted focus:ring-2 focus:ring-purple-active focus:border-transparent text-sm"
                        />
                      </div>

                      <button
                        onClick={handleGenerateToken}
                        disabled={isGenerating}
                        className="w-full px-4 py-2 text-sm font-medium text-white bg-purple-active hover:bg-purple-active/80 rounded-lg disabled:opacity-50 flex items-center justify-center gap-2"
                      >
                        {isGenerating ? (
                          <>
                            <RefreshCw className="w-4 h-4 animate-spin" />
                            Generating...
                          </>
                        ) : (
                          <>
                            <Plus className="w-4 h-4" />
                            Generate New Token
                          </>
                        )}
                      </button>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary">
                          Registration Token
                        </label>
                        <button
                          onClick={() => { setSelectedToken(''); setTokenDescription(''); }}
                          className="text-xs text-purple-active hover:text-purple-active/80 flex items-center gap-1"
                        >
                          <X className="w-3 h-3" />
                          Use different token
                        </button>
                      </div>
                      <div className="p-3 bg-gray-100 dark:bg-charcoal-darkest rounded-lg font-mono text-sm text-gray-700 dark:text-amber-primary break-all">
                        {selectedToken}
                      </div>
                      <div className="p-2 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded">
                        <p className="text-xs text-yellow-800 dark:text-yellow-300">
                          ⚠️ This is a single-use token. Copy the install command below to register the agent.
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Command Block with Copy Button */}
                  {selectedToken && (
                    <>
                      <div className="relative">
                        <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg text-sm overflow-x-hidden whitespace-pre-wrap break-all pr-12">
                          <code>{`curl -sL https://raw.githubusercontent.com/ubenmackin/runic/main/scripts/install-agent.sh | sudo bash -s -- ${controlPlaneUrl} ${selectedToken}`}</code>
                        </pre>
                        <button
                          onClick={copyToClipboard}
                          className="absolute top-3 right-3 p-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
                          title="Copy to clipboard"
                        >
                          {copied ? (
                            <Check className="w-4 h-4 text-green-400" />
                          ) : (
                            <Copy className="w-4 h-4 text-gray-300" />
                          )}
                        </button>
                      </div>

                      {copied && (
                        <p className="text-sm text-green-600 dark:text-green-400">
                          Copied!
                        </p>
                      )}
                    </>
                  )}

                  <div className="bg-blue-50 dark:bg-purple-active/10 border border-blue-200 dark:border-purple-active/30 rounded-lg p-3">
                    <p className="text-sm text-blue-700 dark:text-purple-active">
                      New agents require a registration token for secure registration. Existing agents will auto-re-register when upgrading — no token needed.
                    </p>
                  </div>
                </div>
              )}

              {activeTab === 'manual' && (
                <form onSubmit={handleManualSubmit} className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                      Name <span className="text-red-500">*</span>
                    </label>
                    <input
                      type="text"
                      value={manualForm.hostname}
                      onChange={(e) => setManualForm(f => ({ ...f, hostname: e.target.value }))}
                      placeholder="e.g., HP-Printer, NAS, Bens-iPhone"
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral focus:ring-2 focus:ring-purple-active focus:border-transparent"
                    />
                    {manualErrors.hostname && (
                      <p className="text-sm text-red-500 mt-1">{manualErrors.hostname}</p>
                    )}
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                      IP Address or CIDR <span className="text-red-500">*</span>
                    </label>
                    <input
                      type="text"
                      value={manualForm.ip_address}
                      onChange={(e) => setManualForm(f => ({ ...f, ip_address: e.target.value }))}
                      placeholder="e.g., 10.0.0.0/8, 192.168.1.50"
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral focus:ring-2 focus:ring-purple-active focus:border-transparent"
                    />
                    {manualErrors.ip_address && (
                      <p className="text-sm text-red-500 mt-1">{manualErrors.ip_address}</p>
                    )}
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                      Operating System <span className="text-red-500">*</span>
                    </label>
                    <SearchableSelect
                      options={OS_OPTIONS}
                      value={manualForm.os_type}
                      onChange={(v) => setManualForm(f => ({ ...f, os_type: v }))}
                      placeholder="Select OS"
                    />
                    {manualErrors.os_type && (
                      <p className="text-sm text-red-500 mt-1">{manualErrors.os_type}</p>
                    )}
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                      Architecture
                    </label>
                    <SearchableSelect
                      options={ARCH_OPTIONS}
                      value={manualForm.arch}
                      onChange={(v) => setManualForm(f => ({ ...f, arch: v }))}
                      placeholder="Select Architecture"
                    />
                  </div>

                  {manualErrors._general && (
                    <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                      <p className="text-sm text-red-700 dark:text-red-300">{manualErrors._general}</p>
                    </div>
                  )}

                  <div className="flex justify-end gap-3 pt-2">
                    <button
                      type="button"
                      onClick={closeAddModal}
                      className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-lg hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="px-4 py-2 text-sm font-medium text-white bg-purple-active hover:bg-purple-active/80 rounded-lg"
                    >
                      Add Manual Peer
                    </button>
                  </div>
                </form>
	)}
	</div>
	</div>
	</div>
	)}

  {/* Pending Changes Modal */}
  {pendingModalOpen && pendingModalPeer && (
    <PendingChangesModal
      peerId={pendingModalPeer.id}
      peerHostname={pendingModalPeer.hostname}
      onClose={() => { setPendingModalOpen(false); setPendingModalPeer(null) }}
      onApplied={() => {
        qc.invalidateQueries({ queryKey: QUERY_KEYS.peers() })
        qc.invalidateQueries({ queryKey: ['pending-changes'] })
      }}
    />
  )}
	</div>
	)
	}
