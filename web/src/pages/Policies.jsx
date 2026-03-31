import { useState, useMemo, useCallback, useRef, useEffect } from 'react'
import { useFilterPersistence } from '../hooks/useFilterPersistence'
import { useTableSort } from '../hooks/useTableSort'
import { usePagination } from '../hooks/usePagination'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Pencil, Trash2, Eye, RefreshCw, X, ChevronDown, ChevronUp, Info, Search, ChevronLeft, ChevronRight, ArrowLeft, ArrowRight } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useCrudModal } from '../hooks/useCrudModal'
import { useToastContext } from '../hooks/ToastContext'
import ConfirmModal from '../components/ConfirmModal'
import SearchableSelect from '../components/SearchableSelect'
import ToggleSwitch from '../components/ToggleSwitch'
import InlineError from '../components/InlineError'
import EmptyState from '../components/EmptyState'
import TableSkeleton from '../components/TableSkeleton'
import SortIndicator from '../components/SortIndicator'

// Special targets - predefined network addresses for broadcast/multicast
const SPECIAL_TARGETS = {
  SUBNET_BROADCAST: { id: 1, name: '__subnet_broadcast__', label: 'Subnet Broadcast' },
  LIMITED_BROADCAST: { id: 2, name: '__limited_broadcast__', label: 'Limited Broadcast' },
  ALL_HOSTS: { id: 3, name: '__all_hosts__', label: 'All Hosts (IGMP)' },
  MDNS: { id: 4, name: '__mdns__', label: 'mDNS' },
}

export default function Policies() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const { modalOpen, setModalOpen, editItem: editPolicy, setEditItem: setEditPolicy, form: formData, setForm: setFormData, setFormForEdit, handleOpenAdd, handleCancel } = useCrudModal({ 
    name: '', 
    description: '', 
    source_id: '', 
    source_type: 'group', 
    service_id: '', 
    target_id: '', 
    target_type: 'peer', 
    action: 'ACCEPT', 
    priority: 100, 
    enabled: true, 
    docker_only: false,
    direction: 'both'
  })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [filterPeer, setFilterPeer] = useState(null)
  const { value: showDisabled, setValue: setShowDisabled } = useFilterPersistence('policies', 'showDisabled', false)
  const [preview, setPreview] = useState(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [formErrors, setFormErrors] = useState({})
  const [showSystemRules, setShowSystemRules] = useState(false)

  // Sorting state (persisted per-user)
  const { sortConfig, handleSort } = useTableSort('policies', { key: 'priority', direction: 'asc' })

  // Manual refresh state
  const [isManualRefreshing, setIsManualRefreshing] = useState(false)

  // Modal ref for focus trap
  const modalRef = useRef(null)

  // Focus trap for modal accessibility
  useEffect(() => {
    if (!modalOpen) return
    const modal = modalRef.current
    if (!modal) return

    const focusableElements = modal.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    )
    const firstElement = focusableElements[0]
    const lastElement = focusableElements[focusableElements.length - 1]

    // Focus first element on open
    firstElement?.focus()

    const handleKeyDown = (e) => {
      if (e.key === 'Tab') {
        if (e.shiftKey && document.activeElement === firstElement) {
          e.preventDefault()
          lastElement?.focus()
        } else if (!e.shiftKey && document.activeElement === lastElement) {
          e.preventDefault()
          firstElement?.focus()
        }
      }
    }

    modal.addEventListener('keydown', handleKeyDown)
    return () => modal.removeEventListener('keydown', handleKeyDown)
  }, [modalOpen])

  const openAdd = () => { setFormErrors({}); setPreview(null); handleOpenAdd() }
  const openEdit = (p) => { 
    setEditPolicy(p); 
    setFormForEdit(p); 
    setFormErrors({}); 
    setPreview(null); 
    setModalOpen(true) 
  }
  const closeModal = () => { handleCancel(); setPreview(null) }

  const { data: policies, isLoading, refetch } = useQuery({
    queryKey: QUERY_KEYS.policies(),
    queryFn: () => api.get('/policies'),
  })

  // Manual refresh handler
  const handleManualRefresh = useCallback(async () => {
    setIsManualRefreshing(true)
    await refetch()
    setIsManualRefreshing(false)
  }, [refetch])

  const { data: peers } = useQuery({
    queryKey: QUERY_KEYS.peers(),
    queryFn: () => api.get('/peers'),
  })

  const { data: groups } = useQuery({
    queryKey: QUERY_KEYS.groups(),
    queryFn: () => api.get('/groups'),
  })

const { data: services } = useQuery({
  queryKey: QUERY_KEYS.services(),
  queryFn: () => api.get('/services'),
})

const { data: specialTargets } = useQuery({
  queryKey: ['special-targets'],
  queryFn: () => api.get('/policies/special-targets'),
})

const polymorphicOptions = [
  ...(groups || []).map(g => ({ value: g.id, label: g.name, category: 'group' })),
  ...(peers || []).map(p => ({ value: p.id, label: p.hostname, category: 'peer' })),
  ...(specialTargets || []).map(s => ({ value: s.id, label: s.display_name, category: 'special' }))
]

  const serviceOptions = (services || []).map(s => ({ value: s.id, label: s.name }))

  // Check if the selected target peer has Docker
  const selectedPeerHasDocker = formData.target_type === 'peer' && formData.target_id && peers?.find(p => p.id === formData.target_id)?.has_docker

  const createMutation = useMutation({
    mutationFn: (data) => api.post('/policies', data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.policies() }); closeModal() },
    onError: (err) => setFormErrors({ _general: err.message }),
  })

  const updateMutation = useMutation({
    mutationFn: (data) => api.put(`/policies/${editPolicy.id}`, data),
    onMutate: async (newData) => {
      await qc.cancelQueries({ queryKey: QUERY_KEYS.policies() })
      const previousPolicies = qc.getQueryData(QUERY_KEYS.policies())
      qc.setQueryData(QUERY_KEYS.policies(), old => old?.map(p => p.id === editPolicy.id ? { ...p, ...newData } : p) || [])
      return { previousPolicies }
    },
    onError: (err, newData, context) => {
      qc.setQueryData(QUERY_KEYS.policies(), context.previousPolicies)
      setFormErrors({ _general: err.message })
    },
    onSettled: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.policies() }); closeModal() },
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => api.delete(`/policies/${id}`),
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey: QUERY_KEYS.policies() })
      const previousPolicies = qc.getQueryData(QUERY_KEYS.policies())
      qc.setQueryData(QUERY_KEYS.policies(), old => old?.filter(p => p.id !== id) || [])
      return { previousPolicies }
    },
    onError: (err, id, context) => {
      qc.setQueryData(QUERY_KEYS.policies(), context.previousPolicies)
      showToast(err.message, 'error')
    },
    onSettled: () => { setDeleteTarget(null) },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }) => api.patch(`/policies/${id}`, { enabled }),
    onMutate: async ({ id, enabled }) => {
      await qc.cancelQueries({ queryKey: QUERY_KEYS.policies() })
      const prev = qc.getQueryData(QUERY_KEYS.policies())
      qc.setQueryData(QUERY_KEYS.policies(), old => old?.map(p => p.id === id ? { ...p, enabled } : p))
      return { prev }
    },
    onError: (err, vars, ctx) => qc.setQueryData(QUERY_KEYS.policies(), ctx.prev),
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    if (editPolicy) updateMutation.mutate(formData)
    else createMutation.mutate(formData)
  }

  const fetchPreview = async () => {
    if (!formData.source_id || !formData.service_id || !formData.target_id) {
      setFormErrors({ _general: 'Select source, service, and target to preview' })
      return
    }
    setPreviewLoading(true)
    try {
      const data = await api.post('/policies/preview', { 
        source_id: formData.source_id, 
        source_type: formData.source_type,
        service_id: formData.service_id, 
        target_id: formData.target_id,
        target_type: formData.target_type,
        direction: formData.direction
      })
      setPreview(data)
      setFormErrors({})
    } catch (err) {
      setFormErrors({ _general: err.message })
    } finally {
      setPreviewLoading(false)
    }
  }

  const getEntityName = (type, id) => {
    if (type === 'peer') return peers?.find(p => p.id === id)?.hostname || id
    if (type === 'group') return groups?.find(g => g.id === id)?.name || id
    if (type === 'special') return specialTargets?.find(s => s.id === id)?.display_name || id
    return id
  }
  const getServiceName = (id) => services?.find(s => s.id === id)?.name || id

  // Search state
  const [searchTerm, setSearchTerm] = useState('')

  // Processed policies: filter and sort
  const processedPolicies = useMemo(() => {
    if (!policies) return []

    // Filter by enabled toggle and peer filter
    let filtered = policies.filter(p => {
      if (!showDisabled && !p.enabled) return false
      if (filterPeer && (p.target_type !== 'peer' || p.target_id !== filterPeer)) return false
      return true
    })

    // Filter by search term
    if (searchTerm) {
      const term = searchTerm.toLowerCase()
      filtered = filtered.filter(p => {
        const name = (p.name || '').toLowerCase()
        const source = getEntityName(p.source_type, p.source_id).toLowerCase()
        const service = getServiceName(p.service_id).toLowerCase()
        const target = getEntityName(p.target_type, p.target_id).toLowerCase()
        return name.includes(term) || source.includes(term) || service.includes(term) || target.includes(term)
      })
    }

    // Sort
    const sorted = [...filtered].sort((a, b) => {
      let aVal, bVal
      switch (sortConfig.key) {
        case 'name':
          aVal = (a.name || '').toLowerCase()
          bVal = (b.name || '').toLowerCase()
          break
        case 'priority':
          aVal = a.priority || 0
          bVal = b.priority || 0
          break
        case 'source':
          aVal = getEntityName(a.source_type, a.source_id).toLowerCase()
          bVal = getEntityName(b.source_type, b.source_id).toLowerCase()
          break
        case 'service':
          aVal = getServiceName(a.service_id).toLowerCase()
          bVal = getServiceName(b.service_id).toLowerCase()
          break
        case 'target':
          aVal = getEntityName(a.target_type, a.target_id).toLowerCase()
          bVal = getEntityName(b.target_type, b.target_id).toLowerCase()
          break
        default:
          return 0
      }
      if (aVal < bVal) return sortConfig.direction === 'asc' ? -1 : 1
      if (aVal > bVal) return sortConfig.direction === 'asc' ? 1 : -1
      return 0
    })
    return sorted
  }, [policies, showDisabled, filterPeer, searchTerm, sortConfig, getEntityName, getServiceName])

  // Pagination state
  const {
    paginatedData: paginatedPolicies,
    totalPages,
    showingRange: policiesShowingRange,
    page: policiesPage,
    rowsPerPage: policiesRowsPerPage,
    onPageChange: setPoliciesPage,
    onRowsPerPageChange: setPoliciesRowsPerPage,
    totalItems: policiesTotal
  } = usePagination(processedPolicies, 'policies')

  // Reset page to 1 when search term changes
  useEffect(() => {
    setPoliciesPage(1)
  }, [searchTerm])

  if (isLoading) return <TableSkeleton rows={3} columns={7} />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-light-neutral">Policies</h1>
          <p className="text-gray-600 dark:text-amber-muted">Create firewall rules to control network traffic between groups and peers</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleManualRefresh}
            disabled={isManualRefreshing}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-lg hover:bg-gray-50 dark:hover:bg-charcoal-darkest disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isManualRefreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button onClick={openAdd} className="flex items-center gap-2 px-4 py-2 bg-purple-active hover:bg-purple-active/80 text-white text-sm font-medium rounded-lg">
            <Plus className="w-4 h-4" /> New Policy
          </button>
        </div>
</div>

{/* System Rules Info Panel */}
<div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm overflow-hidden">
  <button
    type="button"
    onClick={() => setShowSystemRules(!showSystemRules)}
    className="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-gray-50 dark:hover:bg-charcoal-darkest transition-colors"
  >
    <div className="flex items-center gap-2">
      <Info className="w-5 h-5 text-blue-500" />
      <span className="font-medium text-gray-900 dark:text-light-neutral">System Rules</span>
      <span className="text-xs text-gray-500 dark:text-amber-muted">(Automatically applied)</span>
    </div>
    {showSystemRules ? (
      <ChevronUp className="w-5 h-5 text-gray-500" />
    ) : (
      <ChevronDown className="w-5 h-5 text-gray-500" />
    )}
  </button>
  {showSystemRules && (
    <div className="px-4 pb-4 border-t border-gray-200 dark:border-gray-border">
      <div className="mt-3 space-y-2 text-sm">
        <div className="flex items-start gap-2">
          <span className="text-green-500 mt-0.5">✓</span>
          <div>
							<span className="font-medium text-gray-700 dark:text-amber-primary">ICMP Error Messages:</span>
							<span className="text-gray-600 dark:text-amber-muted ml-1">ICMP error messages (Destination Unreachable, Time Exceeded, etc.) for allowed connections are accepted.</span>
          </div>
        </div>
<div className="flex items-start gap-2">
                                <span className="text-red-500 mt-0.5">✕</span>
                                <div>
                                    <span className="font-medium text-gray-700 dark:text-amber-primary">Invalid Packets:</span>
                                    <span className="text-gray-600 dark:text-amber-muted ml-1">Packets with invalid state are dropped.</span>
                                </div>
                            </div>
                            <div className="flex items-start gap-2">
                                <span className="text-green-500 mt-0.5">✓</span>
                                <div>
                                    <span className="font-medium text-gray-700 dark:text-amber-primary">Control Plane Communication:</span>
                                    <span className="text-gray-600 dark:text-amber-muted ml-1">Agents can always communicate with the control plane for heartbeats and rule updates.</span>
                                </div>
                            </div>
                        </div>
    </div>
  )}
</div>

 {/* Filters */}
<div className="flex flex-wrap gap-4 items-center">
  <div className="relative max-w-md flex-1">
    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
    <input
      type="text"
      placeholder="Search policies by name, source, service, or target..."
      value={searchTerm}
      onChange={(e) => setSearchTerm(e.target.value)}
      className="w-full pl-9 pr-10 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral placeholder-gray-400 focus:ring-2 focus:ring-purple-active focus:border-purple-active"
    />
    {searchTerm && (
      <button
        onClick={() => setSearchTerm('')}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-light-neutral"
      >
        <X className="w-4 h-4" />
      </button>
    )}
  </div>
  <div className="w-48">
    <SearchableSelect options={[{ value: '', label: 'All Peers', category: 'peer' }, ...polymorphicOptions.filter(o => o.category === 'peer')]} value={filterPeer || ''} onChange={v => setFilterPeer(v || null)} placeholder="Filter by peer" />
  </div>
  <label className="flex items-center gap-2 cursor-pointer">
    <ToggleSwitch checked={showDisabled} onChange={setShowDisabled} />
    <span className="text-sm text-gray-700 dark:text-amber-primary">Show disabled</span>
  </label>
  <div className="flex items-center gap-2">
    <span className="text-sm text-gray-500 dark:text-amber-muted">Rows:</span>
    <select
      value={policiesRowsPerPage}
      onChange={(e) => setPoliciesRowsPerPage(Number(e.target.value))}
      className="text-sm border border-gray-300 dark:border-gray-border rounded px-2 py-2 bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral focus:ring-2 focus:ring-purple-active focus:border-purple-active"
    >
      <option value={10}>10</option>
      <option value={25}>25</option>
      <option value={50}>50</option>
      <option value={100}>100</option>
      <option value={-1}>All</option>
    </select>
  </div>
</div>

{!processedPolicies.length ? (
        searchTerm ? (
          <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm p-8 text-center">
            <p className="text-gray-500 dark:text-amber-muted">No policies match your search.</p>
          </div>
        ) : (
          <EmptyState title="No policies yet" message="Create policies to define firewall rules for your servers." action="New Policy" onAction={openAdd} />
        )
      ) : (
        <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 dark:bg-charcoal-darkest">
                <tr>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted">
                    Enabled
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
            <button type="button" onClick={() => handleSort('name')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
              Name <SortIndicator columnKey="name" sortConfig={sortConfig} />
            </button>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
            <button type="button" onClick={() => handleSort('priority')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
              Priority <SortIndicator columnKey="priority" sortConfig={sortConfig} />
            </button>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
            <button type="button" onClick={() => handleSort('source')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
              Source <SortIndicator columnKey="source" sortConfig={sortConfig} />
            </button>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
            <button type="button" onClick={() => handleSort('service')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
              Service <SortIndicator columnKey="service" sortConfig={sortConfig} />
            </button>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
            <button type="button" onClick={() => handleSort('target')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
              Target <SortIndicator columnKey="target" sortConfig={sortConfig} />
            </button>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted">
                    Action
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted">
                    Direction
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-border">
                {paginatedPolicies.map((p) => (
                  <tr key={p.id}>
                    <td className="px-4 py-3">
                      <ToggleSwitch checked={p.enabled} onChange={(v) => toggleMutation.mutate({ id: p.id, enabled: v })} />
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-medium text-gray-900 dark:text-light-neutral">{p.name}</span>
                    </td>
                    <td className="px-4 py-3 text-gray-600 dark:text-amber-primary">
                      {p.priority}
                    </td>
                    <td className="px-4 py-3 text-gray-600 dark:text-amber-primary">
                      {getEntityName(p.source_type, p.source_id)}
                    </td>
                    <td className="px-4 py-3 text-gray-600 dark:text-amber-primary">
                      {getServiceName(p.service_id)}
                    </td>
                    <td className="px-4 py-3 text-gray-600 dark:text-amber-primary">
                      {getEntityName(p.target_type, p.target_id)}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${p.action === 'ACCEPT' ? 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300'}`}>
                        {p.action.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        {(p.direction === 'both' || p.direction === 'forward') && (
                          <span className="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-400" title="Forward (Source → Target)">
                            <ArrowRight className="w-3 h-3" />
                          </span>
                        )}
                        {(p.direction === 'both' || p.direction === 'backward') && (
                          <span className="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-400" title="Backward (Target → Source)">
                            <ArrowLeft className="w-3 h-3" />
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button onClick={() => openEdit(p)} className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded" title="Edit">
                          <Pencil className="w-4 h-4 text-gray-500" />
                        </button>
                        <button onClick={() => setDeleteTarget(p)} className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded" title="Delete">
                          <Trash2 className="w-4 h-4 text-red-500" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          {policiesTotal > 0 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 dark:border-gray-border bg-gray-50 dark:bg-charcoal-darkest">
              <span className="text-sm text-gray-500 dark:text-amber-muted">
                {policiesShowingRange}
              </span>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setPoliciesPage(policiesPage - 1)}
                  disabled={policiesPage <= 1}
                  className="p-1.5 rounded hover:bg-gray-200 dark:hover:bg-charcoal-dark disabled:opacity-40 disabled:cursor-not-allowed"
                  title="Previous page"
                >
                  <ChevronLeft className="w-5 h-5 text-gray-600 dark:text-amber-primary" />
                </button>
                <span className="px-3 text-sm text-gray-600 dark:text-amber-primary">
                  Page {policiesPage} of {totalPages}
                </span>
                <button
                  onClick={() => setPoliciesPage(policiesPage + 1)}
                  disabled={policiesPage >= totalPages}
                  className="p-1.5 rounded hover:bg-gray-200 dark:hover:bg-charcoal-dark disabled:opacity-40 disabled:cursor-not-allowed"
                  title="Next page"
                >
                  <ChevronRight className="w-5 h-5 text-gray-600 dark:text-amber-primary" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" tabIndex="-1" onKeyDown={(e) => { if (e.key === 'Escape') { closeModal() } }}>
          <div ref={modalRef} className="bg-white dark:bg-charcoal-dark rounded-xl shadow-xl w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border flex items-center justify-between">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">{editPolicy ? 'Edit Policy' : 'New Policy'}</h3>
              <button type="button" onClick={closeModal} className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded">
                <X className="w-5 h-5 text-gray-400" />
              </button>
            </div>
            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="col-span-2 sm:col-span-1">
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Name</label>
                  <input autoFocus type="text" value={formData.name} onChange={e => setFormData(d => ({ ...d, name: e.target.value }))} required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-purple-active" />
                </div>
                <div className="col-span-2 sm:col-span-1">
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Priority</label>
                  <input type="number" value={formData.priority} onChange={e => setFormData(d => ({ ...d, priority: parseInt(e.target.value) || 100 }))} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-purple-active" />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Description</label>
                <textarea value={formData.description} onChange={e => setFormData(d => ({ ...d, description: e.target.value }))} rows={2} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-purple-active" />
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-[1fr_auto_1fr] gap-x-4 gap-y-4 items-end">
                {/* Row 1: Source - Direction - Target */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Source</label>
                  <SearchableSelect options={polymorphicOptions} value={formData.source_id} category={formData.source_type} onChange={(v, type) => setFormData(d => ({ ...d, source_id: v, source_type: type }))} placeholder="Select group or peer" />
                </div>
                <div className="flex flex-col items-center justify-end gap-1.5 pb-0.5">
                  <div className="flex flex-col gap-1.5">
                    <button
                      type="button"
                      onClick={() => {
                        if (formData.direction === 'forward') return
                        setFormData(d => ({
                          ...d,
                          direction: d.direction === 'both' ? 'backward' : (d.direction === 'backward' ? 'both' : 'forward')
                        }))
                      }}
                      className={`flex items-center justify-center w-28 h-8 rounded-xl border-2 transition-all duration-200 ${
                        formData.direction === 'both' || formData.direction === 'forward'
                          ? 'bg-emerald-900/80 border-emerald-500 text-emerald-400 hover:bg-emerald-800/80'
                          : 'bg-gray-200 dark:bg-gray-800 border-gray-300 dark:border-gray-600 text-gray-400 dark:text-gray-500 hover:bg-gray-300 dark:hover:bg-gray-700'
                      }`}
                      title="Forward: Source → Target"
                    >
                      <svg viewBox="0 0 80 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="w-16 h-4">
                        <line x1="8" y1="12" x2="66" y2="12" />
                        <polyline points="58,6 66,12 58,18" />
                      </svg>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        if (formData.direction === 'backward') return
                        setFormData(d => ({
                          ...d,
                          direction: d.direction === 'both' ? 'forward' : (d.direction === 'forward' ? 'both' : 'backward')
                        }))
                      }}
                      className={`flex items-center justify-center w-28 h-8 rounded-xl border-2 transition-all duration-200 ${
                        formData.direction === 'both' || formData.direction === 'backward'
                          ? 'bg-emerald-900/80 border-emerald-500 text-emerald-400 hover:bg-emerald-800/80'
                          : 'bg-gray-200 dark:bg-gray-800 border-gray-300 dark:border-gray-600 text-gray-400 dark:text-gray-500 hover:bg-gray-300 dark:hover:bg-gray-700'
                      }`}
                      title="Backward: Target → Source"
                    >
                      <svg viewBox="0 0 80 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="w-16 h-4">
                        <line x1="72" y1="12" x2="14" y2="12" />
                        <polyline points="22,6 14,12 22,18" />
                      </svg>
                    </button>
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Target</label>
                  <SearchableSelect options={polymorphicOptions} value={formData.target_id} category={formData.target_type} onChange={(v, type) => setFormData(d => ({ ...d, target_id: v, target_type: type }))} placeholder="Select group or peer" />
                </div>

                {/* Row 2: Service - (empty) - Action */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Service</label>
                  <SearchableSelect options={serviceOptions} value={formData.service_id} onChange={v => setFormData(d => ({ ...d, service_id: v }))} placeholder="Select service" />
                </div>
                <div>{/* spacer */}</div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Action</label>
                  <div className="flex gap-4 pt-2">
                    <label className="flex items-center gap-2 cursor-pointer group">
                      <input type="radio" name="action" value="ACCEPT" checked={formData.action === 'ACCEPT'} onChange={e => setFormData(d => ({ ...d, action: e.target.value }))} className="text-purple-active focus:ring-purple-active bg-white dark:bg-charcoal-dark border-gray-300 dark:border-gray-border" />
                      <span className="text-sm text-green-700 dark:text-green-400 font-medium group-hover:opacity-80">ACCEPT</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer group">
                      <input type="radio" name="action" value="LOG_DROP" checked={formData.action === 'LOG_DROP'} onChange={e => setFormData(d => ({ ...d, action: e.target.value }))} className="text-purple-active focus:ring-purple-active bg-white dark:bg-charcoal-dark border-gray-300 dark:border-gray-border" />
                      <span className="text-sm text-red-700 dark:text-red-400 font-medium group-hover:opacity-80">LOG+DROP</span>
                    </label>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-3 py-1">
                <ToggleSwitch checked={formData.enabled} onChange={v => setFormData(d => ({ ...d, enabled: v }))} />
                <label className="text-sm text-gray-700 dark:text-amber-primary cursor-pointer">Policy enabled</label>
              </div>

              {/* Docker Only Toggle - Only shown when target is a peer and has Docker */}
              {selectedPeerHasDocker && (
                <div className="flex items-center gap-2 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
                  <ToggleSwitch checked={formData.docker_only} onChange={v => setFormData(d => ({ ...d, docker_only: v }))} />
                  <label className="text-sm text-gray-700 dark:text-amber-primary">Docker containers only</label>
                  <span className="text-xs text-gray-500 dark:text-amber-muted ml-1">(Apply to DOCKER-USER chain only)</span>
                </div>
              )}

              {/* Preview */}
              <div className="border-t border-gray-200 dark:border-gray-border pt-4">
                <button type="button" onClick={fetchPreview} disabled={previewLoading} className="flex items-center gap-2 text-sm text-purple-active hover:opacity-80 mb-2 font-medium">
                  <Eye className="w-4 h-4" /> {previewLoading ? 'Generating preview...' : 'Preview Rules'}
                </button>
                {preview && (
                  <div className="p-3 bg-gray-900 dark:bg-charcoal-darkest rounded-lg text-xs font-mono border border-gray-800">
                    {preview.rules?.map((rule, i) => (
                      <p key={i} className="text-green-400">{rule}</p>
                    ))}
                    {!preview.rules?.length && <p className="text-gray-500 italic">No rules generated for this orientation.</p>}
                  </div>
                )}
              </div>

              <InlineError message={formErrors._general} />
              <div className="flex justify-end gap-3 pt-6">
                <button type="button" onClick={closeModal} className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-lg hover:bg-gray-50 dark:hover:bg-charcoal-darkest">Cancel</button>
                <button type="submit" className="px-4 py-2 text-sm font-medium text-white bg-purple-active hover:bg-purple-active/80 rounded-lg transition-colors">{editPolicy ? 'Save Changes' : 'Create Policy'}</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {deleteTarget && (
        <ConfirmModal
          title="Delete Policy"
          message={`Delete policy "${deleteTarget.name}"? Rules will be removed from ${getEntityName(deleteTarget.target_type, deleteTarget.target_id)} on next push.`}
          onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
          onCancel={() => setDeleteTarget(null)}
          danger
        />
      )}
    </div>
  )
}
