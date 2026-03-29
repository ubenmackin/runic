import { useState, useMemo, useCallback, useRef, useEffect } from 'react'
import { useTableSort } from '../hooks/useTableSort'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Pencil, Trash2, Eye, RefreshCw, ArrowUp, ArrowDown, ArrowUpDown, X, ChevronDown, ChevronUp, Info, Search } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useCrudModal } from '../hooks/useCrudModal'
import { useToastContext } from '../hooks/ToastContext'
import ConfirmModal from '../components/ConfirmModal'
import SearchableSelect from '../components/SearchableSelect'
import ToggleSwitch from '../components/ToggleSwitch'
import InlineError from '../components/InlineError'
import EmptyState from '../components/EmptyState'
import TableSkeleton from '../components/TableSkeleton'

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
    docker_only: false 
  })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [filterPeer, setFilterPeer] = useState(null)
  const [showDisabled, setShowDisabled] = useState(false)
  const [preview, setPreview] = useState(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [formErrors, setFormErrors] = useState({})
  const [showSystemRules, setShowSystemRules] = useState(false)

  // Sorting state (persisted per-user)
  const { sortConfig, handleSort } = useTableSort('policies', { key: 'priority', direction: 'asc' })

  // Search state
  const [searchTerm, setSearchTerm] = useState('')

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

  const polymorphicOptions = [
    ...(groups || []).map(g => ({ value: g.id, label: g.name, category: 'group' })),
    ...(peers || []).map(p => ({ value: p.id, label: p.hostname, category: 'peer' }))
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
        target_type: formData.target_type
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
    return id
  }
  const getServiceName = (id) => services?.find(s => s.id === id)?.name || id

  // Sort indicator component
  const SortIndicator = ({ columnKey }) => {
    if (sortConfig.key !== columnKey) {
      return <ArrowUpDown className="w-4 h-4 ml-1 opacity-40 inline-block" />
    }
    return sortConfig.direction === 'asc'
      ? <ArrowUp className="w-4 h-4 ml-1 inline-block" />
      : <ArrowDown className="w-4 h-4 ml-1 inline-block" />
  }

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
            <span className="font-medium text-gray-700 dark:text-amber-primary">Established/Related:</span>
            <span className="text-gray-600 dark:text-amber-muted ml-1">Traffic from established and related connections is always accepted.</span>
          </div>
        </div>
        <div className="flex items-start gap-2">
          <span className="text-red-500 mt-0.5">✕</span>
          <div>
            <span className="font-medium text-gray-700 dark:text-amber-primary">Invalid Packets:</span>
            <span className="text-gray-600 dark:text-amber-muted ml-1">Packets with invalid state are dropped.</span>
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
                  <th
                    className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted cursor-pointer hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none"
                    onClick={() => handleSort('name')}
                  >
                    Name <SortIndicator columnKey="name" />
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted cursor-pointer hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none"
                    onClick={() => handleSort('priority')}
                  >
                    Priority <SortIndicator columnKey="priority" />
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted cursor-pointer hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none"
                    onClick={() => handleSort('source')}
                  >
                    Source <SortIndicator columnKey="source" />
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted cursor-pointer hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none"
                    onClick={() => handleSort('service')}
                  >
                    Service <SortIndicator columnKey="service" />
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted cursor-pointer hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none"
                    onClick={() => handleSort('target')}
                  >
                    Target <SortIndicator columnKey="target" />
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted">
                    Action
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-border">
                {processedPolicies.map((p) => (
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
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${p.action === 'accept' ? 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300'}`}>
                        {p.action.toUpperCase()}
                      </span>
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
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Source</label>
                  <SearchableSelect options={polymorphicOptions} value={formData.source_id} onChange={(v, type) => setFormData(d => ({ ...d, source_id: v, source_type: type }))} placeholder="Select group or peer" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Service</label>
                  <SearchableSelect options={serviceOptions} value={formData.service_id} onChange={v => setFormData(d => ({ ...d, service_id: v }))} placeholder="Select service" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Target</label>
                  <SearchableSelect options={polymorphicOptions} value={formData.target_id} onChange={(v, type) => setFormData(d => ({ ...d, target_id: v, target_type: type }))} placeholder="Select group or peer" />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Action</label>
                <div className="flex gap-4">
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
                <button type="button" onClick={closeModal} className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-light-neutral bg-gray-100 dark:bg-charcoal-darkest rounded-lg hover:bg-black hover:text-white dark:hover:bg-black transition-colors">Cancel</button>
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
