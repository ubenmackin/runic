import { useState, useMemo, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Pencil, Trash2, Server, Copy, Check, RefreshCw, ArrowUp, ArrowDown, ArrowUpDown } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { REFETCH_INTERVALS } from '../constants'
import { useCrudModal } from '../hooks/useCrudModal'
import { useToastContext } from '../hooks/ToastContext'
import ConfirmModal from '../components/ConfirmModal'
import SearchableSelect from '../components/SearchableSelect'
import InlineError from '../components/InlineError'
import EmptyState from '../components/EmptyState'
import TableSkeleton from '../components/TableSkeleton'

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
]

// Helper function to format relative time
function formatRelativeTime(timestamp) {
  if (!timestamp) return 'Never'
  
  const date = new Date(timestamp)
  const now = new Date()
  const diffMs = now - date
  const diffSeconds = Math.floor(diffMs / 1000)
  const diffMinutes = Math.floor(diffSeconds / 60)
  const diffHours = Math.floor(diffMinutes / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffSeconds < 60) return 'Just now'
  if (diffMinutes < 60) return `${diffMinutes} minute${diffMinutes !== 1 ? 's' : ''} ago`
  if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`
  if (diffDays < 7) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`
  
  // For older dates, show the actual date
  return date.toLocaleDateString()
}

// Helper function to parse heartbeat for sorting
function parseHeartbeatForSort(timestamp) {
  if (!timestamp) return 0
  return new Date(timestamp).getTime()
}

export default function Peers() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const { modalOpen, setModalOpen, editItem: editPeer, setEditItem: setEditPeer, form: formData, setForm: setFormData, setFormForEdit, handleOpenAdd, handleCancel: closeModal } = useCrudModal({ hostname: '', ip_address: '', os: 'ubuntu', arch: 'amd64', has_docker: false, description: '' })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [formErrors, setFormErrors] = useState({})

  // Add Peer modal state
  const [addModalOpen, setAddModalOpen] = useState(false)
  const [activeTab, setActiveTab] = useState('agent') // 'agent' or 'manual'
  const [manualForm, setManualForm] = useState({ hostname: '', ip_address: '', os_type: 'other' })
  const [manualErrors, setManualErrors] = useState({})
  const [copied, setCopied] = useState(false)

  // Sorting state
  const [sortConfig, setSortConfig] = useState({ key: 'hostname', direction: 'asc' })

  // Search state
  const [searchTerm, setSearchTerm] = useState('')

  // Manual refresh state
  const [isManualRefreshing, setIsManualRefreshing] = useState(false)

  const openAdd = () => { setFormErrors({}); handleOpenAdd() }
  const openEdit = (s) => { setEditPeer(s); setFormForEdit(s); setFormErrors({}); setModalOpen(true) }

const openAddModal = () => {
  setAddModalOpen(true)
  setActiveTab('agent')
  setManualForm({ hostname: '', ip_address: '', os_type: 'other' })
  setManualErrors({})
  setCopied(false)
}

const closeAddModal = () => {
  setAddModalOpen(false)
  setManualForm({ hostname: '', ip_address: '', os_type: 'other' })
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

  // Handle sort click
  const handleSort = useCallback((key) => {
    setSortConfig(prev => {
      if (prev.key === key) {
        return { key, direction: prev.direction === 'asc' ? 'desc' : 'asc' }
      }
      return { key, direction: 'asc' }
    })
  }, [])

  // Filtered and sorted data
  const processedPeers = useMemo(() => {
    if (!peers) return []

    // Filter by search term
    let filtered = peers
    if (searchTerm) {
      const term = searchTerm.toLowerCase()
      filtered = peers.filter(peer => {
        const hostname = (peer.hostname || '').toLowerCase()
        const ip = (peer.ip_address || '').toLowerCase()
        const os = (peer.os_type || peer.os || '').toLowerCase()
        const groups = (peer.groups || '').toLowerCase()
        const agent = peer.is_manual ? 'manual' : (peer.agent_version || '').toLowerCase()

        return hostname.includes(term) || ip.includes(term) || os.includes(term) || groups.includes(term) || agent.includes(term)
      })
    }

    // Sort
    const sorted = [...filtered].sort((a, b) => {
      let aVal, bVal

      switch (sortConfig.key) {
        case 'hostname':
          aVal = (a.hostname || '').toLowerCase()
          bVal = (b.hostname || '').toLowerCase()
          break
        case 'ip_address':
          aVal = (a.ip_address || '').toLowerCase()
          bVal = (b.ip_address || '').toLowerCase()
          break
        case 'os_type':
          aVal = (a.os_type || a.os || '').toLowerCase()
          bVal = (b.os_type || b.os || '').toLowerCase()
          break
        case 'last_heartbeat':
          aVal = parseHeartbeatForSort(a.last_heartbeat)
          bVal = parseHeartbeatForSort(b.last_heartbeat)
          break
        default:
          return 0
      }

      if (aVal < bVal) return sortConfig.direction === 'asc' ? -1 : 1
      if (aVal > bVal) return sortConfig.direction === 'asc' ? 1 : -1
      return 0
    })

    return sorted
  }, [peers, searchTerm, sortConfig])

  const createMutation = useMutation({
    mutationFn: (data) => api.post('/peers', data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.peers() }); closeModal() },
    onError: (err) => setFormErrors({ _general: err.message }),
  })

  const updateMutation = useMutation({
    mutationFn: (data) => api.put(`/peers/${editPeer.id}`, data),
    onMutate: async (newData) => {
      await qc.cancelQueries({ queryKey: QUERY_KEYS.peers() })
      const previousPeers = qc.getQueryData(QUERY_KEYS.peers())
      qc.setQueryData(QUERY_KEYS.peers(), old => old?.map(p => p.id === editPeer.id ? { ...p, ...newData } : p) || [])
      return { previousPeers }
    },
    onError: (err, newData, context) => {
      qc.setQueryData(QUERY_KEYS.peers(), context.previousPeers)
      setFormErrors({ _general: err.message })
    },
    onSettled: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.peers() }); closeModal() },
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => api.delete(`/peers/${id}`),
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey: QUERY_KEYS.peers() })
      const previousPeers = qc.getQueryData(QUERY_KEYS.peers())
      qc.setQueryData(QUERY_KEYS.peers(), old => old?.filter(p => p.id !== id) || [])
      return { previousPeers }
    },
    onSuccess: () => {
      showToast('Peer deleted successfully', 'success')
    },
    onError: (err, id, context) => {
      qc.setQueryData(QUERY_KEYS.peers(), context.previousPeers)
      showToast(err.message, 'error')
    },
    onSettled: () => { setDeleteTarget(null) },
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    if (editPeer) updateMutation.mutate(formData)
    else createMutation.mutate(formData)
  }

  // Sort indicator component
  const SortIndicator = ({ columnKey }) => {
    if (sortConfig.key !== columnKey) {
      return <ArrowUpDown className="w-4 h-4 ml-1 opacity-40 inline-block" />
    }
    return sortConfig.direction === 'asc'
      ? <ArrowUp className="w-4 h-4 ml-1 inline-block" />
      : <ArrowDown className="w-4 h-4 ml-1 inline-block" />
  }

  if (isLoading) return <TableSkeleton rows={3} columns={6} />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Peers</h1>
        <div className="flex items-center gap-3">
          <button
            onClick={handleManualRefresh}
            disabled={isManualRefreshing}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isManualRefreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button onClick={openAddModal} className="flex items-center gap-2 px-4 py-2 bg-runic-600 hover:bg-runic-700 text-white text-sm font-medium rounded-lg">
            <Plus className="w-4 h-4" /> Add Peer
          </button>
        </div>
      </div>

      {/* Search Bar */}
      <div className="relative">
        <input
          type="text"
          placeholder="Search peers by hostname, IP, OS, groups, or agent..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:ring-2 focus:ring-runic-500 focus:border-runic-500"
        />
        {searchTerm && (
          <button
            onClick={() => setSearchTerm('')}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
          >
            ×
          </button>
        )}
      </div>

      {!processedPeers?.length ? (
        searchTerm ? (
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-8 text-center">
            <p className="text-gray-500 dark:text-gray-400">No peers match your search.</p>
          </div>
        ) : (
          <EmptyState icon={Server} title="No peers yet" message="Add your first peer to start managing firewall rules." action="Add Peer" onAction={openAddModal} />
        )
      ) : (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 dark:bg-gray-900">
                <tr>
                  <th
                    className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 select-none"
                    onClick={() => handleSort('hostname')}
                  >
                    Hostname <SortIndicator columnKey="hostname" />
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 select-none"
                    onClick={() => handleSort('ip_address')}
                  >
                    IP Address <SortIndicator columnKey="ip_address" />
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 select-none"
                    onClick={() => handleSort('os_type')}
                  >
                    OS <SortIndicator columnKey="os_type" />
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 select-none"
                    onClick={() => handleSort('last_heartbeat')}
                  >
                    Last Heartbeat <SortIndicator columnKey="last_heartbeat" />
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400">
                    Groups
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400">
                    Agent
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {processedPeers.map((peer) => (
                  <tr key={peer.id} className="">
                        <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                                {!peer.is_manual && (
                                    <span className={`w-2 h-2 rounded-full ${
                                        peer.status === 'online' ? 'bg-green-500' :
                                        peer.status === 'offline' ? 'bg-red-500' :
                                        'bg-amber-500' // pending
                                    }`} />
                                )}
                                <span className="font-medium text-gray-900 dark:text-white">{peer.hostname}</span>
                            </div>
                        </td>
                    <td className="px-4 py-3 text-gray-600 dark:text-gray-300">
                      {peer.ip_address}
                    </td>
                    <td className="px-4 py-3 text-gray-600 dark:text-gray-300">
                      {peer.os_type || peer.os || '—'}
                    </td>
                        <td className="px-4 py-3 text-gray-600 dark:text-gray-300">
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
                                  className="px-2 py-0.5 text-xs font-medium rounded-full bg-runic-100 dark:bg-runic-900/30 text-runic-700 dark:text-runic-300 whitespace-nowrap"
                                >
                                  {group}
                                </span>
                              ))}
                              {remainingCount > 0 && (
                                <span
                                  className="px-2 py-0.5 text-xs font-medium rounded-full bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 whitespace-nowrap"
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
                        <span className="px-2 py-1 text-xs font-medium rounded-full bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300">
                          Manual
                        </span>
                      ) : peer.agent_version ? (
                        <span className="text-gray-600 dark:text-gray-300">
                          v{peer.agent_version}
                        </span>
                      ) : (
                        <span className="text-gray-400">—</span>
                      )}
                    </td>
                                <td className="px-4 py-3">
                                    <div className="flex items-center gap-2">
                                        {peer.is_manual && (
                                            <button
                                                onClick={() => openEdit(peer)}
                                                className="p-1.5 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
                                                title="Edit"
                                            >
                                                <Pencil className="w-4 h-4 text-gray-500" />
                                            </button>
                                        )}
                                        <button
                                            onClick={() => setDeleteTarget(peer)}
                                            className="p-1.5 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
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
        </div>
      )}

      {/* Add/Edit Modal (Legacy) */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-xl w-full max-w-lg mx-4">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{editPeer ? 'Edit Peer' : 'Add Peer'}</h3>
            </div>
            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Hostname</label>
                <input type="text" value={formData.hostname} onChange={e => setFormData(d => ({ ...d, hostname: e.target.value }))} required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" />
              </div>
					<div>
						<label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">IP Address</label>
						<input type="text" value={formData.ip_address} onChange={e => setFormData(d => ({ ...d, ip_address: e.target.value }))} required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" />
					</div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">OS</label>
                  <SearchableSelect options={OS_OPTIONS} value={formData.os} onChange={v => setFormData(d => ({ ...d, os: v }))} />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Arch</label>
                  <SearchableSelect options={ARCH_OPTIONS} value={formData.arch} onChange={v => setFormData(d => ({ ...d, arch: v }))} />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Description</label>
                <textarea value={formData.description} onChange={e => setFormData(d => ({ ...d, description: e.target.value }))} rows={2} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" />
              </div>
              <div className="flex items-center gap-2">
                <input type="checkbox" id="has_docker" checked={formData.has_docker} onChange={e => setFormData(d => ({ ...d, has_docker: e.target.checked }))} className="w-4 h-4 rounded border-gray-300" />
                <label htmlFor="has_docker" className="text-sm text-gray-700 dark:text-gray-300">Has Docker</label>
              </div>
              <InlineError message={formErrors._general} />
              <div className="flex justify-end gap-3 pt-2">
                <button type="button" onClick={closeModal} className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg">Cancel</button>
                <button type="submit" className="px-4 py-2 text-sm font-medium text-white bg-runic-600 hover:bg-runic-700 rounded-lg">{editPeer ? 'Save Changes' : 'Add Peer'}</button>
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

      {/* Add Peer Modal with Tabs */}
      {addModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-xl w-full max-w-lg mx-4">
            {/* Header */}
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Add Peer</h3>
              <button
                onClick={closeAddModal}
                className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
              >
                <svg className="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Tab Navigation */}
            <div className="flex border-b border-gray-200 dark:border-gray-700">
              <button
                onClick={() => setActiveTab('agent')}
                className={`flex-1 px-4 py-3 text-sm font-medium text-center border-b-2 transition-colors ${
                  activeTab === 'agent'
                    ? 'border-runic-600 text-runic-600 dark:text-runic-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                Agent Install
              </button>
              <button
                onClick={() => setActiveTab('manual')}
                className={`flex-1 px-4 py-3 text-sm font-medium text-center border-b-2 transition-colors ${
                  activeTab === 'manual'
                    ? 'border-runic-600 text-runic-600 dark:text-runic-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                Manual Entry
              </button>
            </div>

            {/* Tab Content */}
            <div className="p-6">
              {activeTab === 'agent' && (
                <div className="space-y-4">
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Run this command on the target machine to install the agent:
                  </p>

                  {/* Command Block with Copy Button */}
                  <div className="relative">
                    <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg text-sm overflow-x-auto pr-12">
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

                  <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-3">
                    <p className="text-sm text-blue-700 dark:text-blue-300">
                      The agent will auto-register with this control plane. No manual entry needed.
                    </p>
                  </div>
                </div>
              )}

              {activeTab === 'manual' && (
                <form onSubmit={handleManualSubmit} className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Name <span className="text-red-500">*</span>
                    </label>
                    <input
                      type="text"
                      value={manualForm.hostname}
                      onChange={(e) => setManualForm(f => ({ ...f, hostname: e.target.value }))}
                      placeholder="e.g., HP-Printer, NAS, Bens-iPhone"
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-runic-500 focus:border-transparent"
                    />
                    {manualErrors.hostname && (
                      <p className="text-sm text-red-500 mt-1">{manualErrors.hostname}</p>
                    )}
                  </div>

<div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            IP Address or CIDR <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            value={manualForm.ip_address}
            onChange={(e) => setManualForm(f => ({ ...f, ip_address: e.target.value }))}
            placeholder="e.g., 10.0.0.0/8, 192.168.1.50"
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-runic-500 focus:border-transparent"
          />
          {manualErrors.ip_address && (
            <p className="text-sm text-red-500 mt-1">{manualErrors.ip_address}</p>
          )}
        </div>

<div>
  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
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

        {manualErrors._general && (
                    <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                      <p className="text-sm text-red-700 dark:text-red-300">{manualErrors._general}</p>
                    </div>
                  )}

                  <div className="flex justify-end gap-3 pt-2">
                    <button
                      type="button"
                      onClick={closeAddModal}
                      className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-600"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="px-4 py-2 text-sm font-medium text-white bg-runic-600 hover:bg-runic-700 rounded-lg"
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
