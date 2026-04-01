import { useState, useCallback, useRef, useEffect } from 'react'
import { useTableSort } from '../hooks/useTableSort'
import { usePagination } from '../hooks/usePagination'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Pencil, Trash2, Server, Copy, Check, RefreshCw, X, FileCode } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { REFETCH_INTERVALS } from '../constants'
import { useCrudModal } from '../hooks/useCrudModal'
import { useToastContext } from '../hooks/ToastContext'
import { formatRelativeTime } from '../utils/formatTime.js'
import { useFocusTrap } from '../hooks/useFocusTrap'
import { useTableFilter } from '../hooks/useTableFilter'
import { useCrudMutations } from '../hooks/useCrudMutations'
import ConfirmModal from '../components/ConfirmModal'
import SearchableSelect from '../components/SearchableSelect'
import InlineError from '../components/InlineError'
import EmptyState from '../components/EmptyState'
import TableSkeleton from '../components/TableSkeleton'
import SortIndicator from '../components/SortIndicator'
import Pagination from '../components/Pagination'
import TableToolbar from '../components/TableToolbar'
import PageHeader from '../components/PageHeader'

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
  const { modalOpen, setModalOpen, editItem: editPeer, setEditItem: setEditPeer, form: formData, setForm: setFormData, setFormForEdit, handleOpenAdd, handleCancel: closeModal } = useCrudModal({ hostname: '', ip_address: '', os_type: 'ubuntu', arch: 'amd64', has_docker: false, description: '' })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [formErrors, setFormErrors] = useState({})

  // Add Peer modal state
  const [addModalOpen, setAddModalOpen] = useState(false)
  const [activeTab, setActiveTab] = useState('agent') // 'agent' or 'manual'
  const [manualForm, setManualForm] = useState({ hostname: '', ip_address: '', os_type: 'other', arch: 'other' })
  const [manualErrors, setManualErrors] = useState({})
  const [copied, setCopied] = useState(false)

  // Rule Bundle state
  const [bundleModalOpen, setBundleModalOpen] = useState(false)
  const [bundleLoading, setBundleLoading] = useState(false)
  const [bundleContent, setBundleContent] = useState('')
  const [bundlePeer, setBundlePeer] = useState(null)

  const fetchBundle = async (peer) => {
    setBundlePeer(peer)
    setBundleModalOpen(true)
    setBundleLoading(true)
    setBundleContent('')
    try {
      const data = await api.get(`/peers/${peer.id}/bundle`)
      setBundleContent(data.content)
    } catch (err) {
      setBundleContent(`# Error: ${err.message}`)
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

  // Status filter state
  const [statusFilter, setStatusFilter] = useState('all')

  // Manual refresh state
  const [isManualRefreshing, setIsManualRefreshing] = useState(false)

  const openAdd = () => { setFormErrors({}); handleOpenAdd() }
  const openEdit = (s) => { setEditPeer(s); setFormForEdit(s); setFormErrors({}); setModalOpen(true) }

  const openAddModal = () => {
    setAddModalOpen(true)
    setActiveTab('agent')
    setManualForm({ hostname: '', ip_address: '', os_type: 'other', arch: 'other' })
    setManualErrors({})
    setCopied(false)
  }

  const closeAddModal = () => {
    setAddModalOpen(false)
    setManualForm({ hostname: '', ip_address: '', os_type: 'other', arch: 'other' })
    setManualErrors({})
    setCopied(false)
  }

  // Generate agent install command
  const controlPlaneUrl = window.location.origin
  const agentInstallCommand = `curl -sL https://raw.githubusercontent.com/ubenmackin/runic/main/scripts/install-agent.sh | sudo bash -s -- ${controlPlaneUrl}`

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(agentInstallCommand)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      showToast('Failed to copy to clipboard', 'error')
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

  const { createMutation, updateMutation, deleteMutation } = useCrudMutations({
    apiPath: '/peers',
    queryKey: QUERY_KEYS.peers(),
    onCreateSuccess: closeModal,
    onUpdateSuccess: closeModal,
    onDeleteSuccess: () => { setDeleteTarget(null); showToast('Peer deleted successfully', 'success') },
    setFormErrors,
    showToast,
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    if (editPeer) updateMutation.mutate({ id: editPeer.id, data: formData })
    else createMutation.mutate(formData)
  }

  if (isLoading) return <TableSkeleton rows={3} columns={6} />

  return (
    <div className="space-y-4">
      <PageHeader
        title="Peers"
        description="Register and manage devices and endpoints in your network"
        actions={
          <>
            <button
              onClick={handleManualRefresh}
              disabled={isManualRefreshing}
              className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-lg hover:bg-gray-50 dark:hover:bg-charcoal-darkest disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${isManualRefreshing ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <button onClick={openAddModal} className="flex items-center gap-2 px-4 py-2 bg-purple-active hover:bg-purple-active/80 text-white text-sm font-medium rounded-lg">
              <Plus className="w-4 h-4" /> Add Peer
            </button>
          </>
        }
      />

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
                  <button
                    onClick={() => fetchBundle(peer)}
                    className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded"
                    title="View Deployed Rules"
                  >
                    <FileCode className="w-4 h-4 text-purple-active" />
                  </button>
                )}
                {peer.is_manual && (
                          <button
                            onClick={() => openEdit(peer)}
                            className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded"
                            title="Edit"
                          >
                            <Pencil className="w-4 h-4 text-gray-900 dark:text-white" />
                          </button>
                        )}
                        <button
                          onClick={() => setDeleteTarget(peer)}
                          className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4 text-red-500" />
                        </button>
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
          onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
          onCancel={() => setDeleteTarget(null)}
          danger
        />
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
                  <p className="text-sm text-gray-600 dark:text-amber-muted">
                    Run this command on the target machine to install the agent:
                  </p>

                  {/* Command Block with Copy Button */}
                  <div className="relative">
                    <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg text-sm overflow-x-hidden whitespace-pre-wrap break-all pr-12">
                      <code>{agentInstallCommand}</code>
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

                  <div className="bg-blue-50 dark:bg-purple-active/10 border border-blue-200 dark:border-purple-active/30 rounded-lg p-3">
                    <p className="text-sm text-blue-700 dark:text-purple-active">
                      The agent will auto-register with this control plane. No manual entry needed.
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
    </div>
  )
}
