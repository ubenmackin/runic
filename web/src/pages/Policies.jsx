import { useState, useCallback, useRef, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { useFilterPersistence } from '../hooks/useFilterPersistence'
import { useTableSort } from '../hooks/useTableSort'
import { usePagination } from '../hooks/usePagination'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Pencil, Trash2, Eye, RefreshCw, X, ChevronDown, ChevronUp, Info, ArrowLeft, ArrowRight } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useCrudModal } from '../hooks/useCrudModal'
import { useToastContext } from '../hooks/ToastContext'
import { useFocusTrap } from '../hooks/useFocusTrap'
import { useTableFilter } from '../hooks/useTableFilter'
import { useCrudMutations } from '../hooks/useCrudMutations'
import { useAuth } from '../hooks/useAuth'
import ConfirmModal from '../components/ConfirmModal'
import SearchableSelect from '../components/SearchableSelect'
import ToggleSwitch from '../components/ToggleSwitch'
import InlineError from '../components/InlineError'
import EmptyState from '../components/EmptyState'
import TableSkeleton from '../components/TableSkeleton'
import SortIndicator from '../components/SortIndicator'
import Pagination from '../components/Pagination'
import TableToolbar from '../components/TableToolbar'
import PageHeader from '../components/PageHeader'

// Special targets - predefined network addresses for broadcast/multicast
const SPECIAL_TARGETS = {
  SUBNET_BROADCAST: { id: 1, name: '__subnet_broadcast__', label: 'Subnet Broadcast' },
  LIMITED_BROADCAST: { id: 2, name: '__limited_broadcast__', label: 'Limited Broadcast' },
  ALL_HOSTS: { id: 3, name: '__all_hosts__', label: 'All Hosts (IGMP)' },
  MDNS: { id: 4, name: '__mdns__', label: 'mDNS' },
  LOOPBACK: { id: 5, name: '__loopback__', label: 'Loopback' },
  ANY_IP: { id: 6, name: '__any_ip__', label: 'Any IP (0.0.0.0/0)' },
  ALL_PEERS: { id: 7, name: '__all_peers__', label: 'All Peers' },
  IGMPV3: { id: 8, name: '__igmpv3__', label: 'IGMPv3' },
  INTERNET: { id: 9, name: '__internet__', label: 'Internet (all non-private)' },
}

const SYSTEM_RULES = [
  { type: 'accept', title: 'Loopback', description: 'Local loopback interface (lo) traffic is always accepted (both INPUT and OUTPUT).' },
  { type: 'accept', title: 'ICMP Error Messages', description: 'ICMP error messages (Destination Unreachable, Time Exceeded, etc.) for allowed connections are accepted.' },
  { type: 'deny', title: 'Invalid Packets', description: 'Packets with invalid state are dropped.' },
  { type: 'accept', title: 'Control Plane Communication', description: 'Agents can always communicate with the control plane for heartbeats and rule updates (requires control_plane_port configuration).' },
  { type: 'deny', title: 'Default Deny + Logging', description: 'All unmatched INPUT and OUTPUT traffic is logged with prefix "[RUNIC-DROP] " and then dropped.' },
]

export default function Policies() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const { canEdit } = useAuth()
  const location = useLocation()
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
    target_scope: 'both',
    direction: 'both'
  })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [filterPeer, setFilterPeer] = useState(null)
  const { value: showDisabled, setValue: setShowDisabled } = useFilterPersistence('policies', 'showDisabled', false)
  const [preview, setPreview] = useState(null)
  const [previewStale, setPreviewStale] = useState(false)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [formErrors, setFormErrors] = useState({})
  const [activeTab, setActiveTab] = useState('setup')
  const [showSystemRules, setShowSystemRules] = useState(false)
  const [showDescription, setShowDescription] = useState(false)

  // Sorting state (persisted per-user)
  const { sortConfig, handleSort } = useTableSort('policies', { key: 'priority', direction: 'asc' })

  // Manual refresh state
  const [isManualRefreshing, setIsManualRefreshing] = useState(false)

  // Modal ref for focus trap
  const modalRef = useRef(null)

  // Focus trap for modal accessibility
  useFocusTrap(modalRef, modalOpen)

  const openAdd = useCallback(() => {
    setFormErrors({})
    setPreview(null)
    setPreviewStale(false)
    setActiveTab('setup')
    setShowDescription(false)
    handleOpenAdd()
  }, [])
  const openEdit = (p) => {
    setEditPolicy(p);
    setFormForEdit(p);
    setFormErrors({});
    setPreview(null);
    setPreviewStale(false);
    setActiveTab('setup');
    setShowDescription(!!p.description);
    setModalOpen(true)
  }
  const closeModal = () => {
    handleCancel();
    setPreview(null)
  }

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

// Check if the selected service is IGMP
const isIGMPService = formData.service_id && services?.find(s => s.id === formData.service_id)?.name?.toUpperCase() === 'IGMP'

const polymorphicOptions = [
  ...(groups || []).map(g => ({ value: g.id, label: g.name, category: 'group' })),
  ...(peers || []).map(p => ({ 
  value: p.id, 
  label: p.hostname ? `${p.hostname} - ${p.ip_address}` : p.ip_address, 
  category: 'peer' 
})),
  ...(specialTargets || []).map(s => ({ value: s.id, label: s.display_name, category: 'special' }))
]

  const serviceOptions = (services || []).map(s => ({
    value: s.id,
    label: s.name,
    category: s.is_system ? 'System Services' : 'User Services'
  }))

  // Check if any selected peer (source or target) has Docker
  // MD-003: Show "Applies To" when either source or target is a peer with Docker,
  // since target_scope affects DOCKER-USER rule generation for whichever peer the rules compile for
  const selectedPeerHasDocker = (
    (formData.target_type === 'peer' && formData.target_id && peers?.find(p => p.id === formData.target_id)?.has_docker) ||
    (formData.source_type === 'peer' && formData.source_id && peers?.find(p => p.id === formData.source_id)?.has_docker)
  )

  const { createMutation, updateMutation, deleteMutation } = useCrudMutations({
    apiPath: '/policies',
    queryKey: QUERY_KEYS.policies(),
    additionalInvalidations: [['pending-changes']],
    onCreateSuccess: closeModal,
    onUpdateSuccess: closeModal,
    onDeleteSuccess: () => setDeleteTarget(null),
    setFormErrors,
    showToast,
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
    onSettled: () => {
      qc.invalidateQueries({ queryKey: QUERY_KEYS.policies() })
      qc.invalidateQueries({ queryKey: ['pending-changes'] })
    },
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    if (editPolicy) updateMutation.mutate({ id: editPolicy.id, data: formData })
    else createMutation.mutate(formData)
  }

  const fetchPreview = useCallback(async () => {
    // IGMP doesn't require source_id
    if (!formData.service_id || !formData.target_id || (!isIGMPService && !formData.source_id)) {
      setFormErrors({ _general: isIGMPService ? 'Select service and target to preview' : 'Select source, service, and target to preview' })
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
        direction: formData.direction,
        target_scope: formData.target_scope
      })
      setPreview(data)
      setPreviewStale(false)
      setFormErrors({})
    } catch (err) {
      setFormErrors({ _general: err.message })
      setPreviewStale(false)
    } finally {
      setPreviewLoading(false)
    }
  }, [formData, isIGMPService])

  const initialFormRender = useRef(true);

  // Mark preview stale whenever form data changes
  useEffect(() => {
    if (initialFormRender.current) {
      initialFormRender.current = false;
      return;
    }
    setPreviewStale(true);
  }, [formData]);

  // Auto-fetch preview when switching to Preview tab
  useEffect(() => {
    if (activeTab === 'preview' && previewStale && !previewLoading) {
      fetchPreview()
    }
  }, [activeTab, previewStale, previewLoading, fetchPreview])

  const getEntityName = useCallback((type, id) => {
    if (type === 'peer') return peers?.find(p => p.id === id)?.hostname || id
    if (type === 'group') return groups?.find(g => g.id === id)?.name || id
    if (type === 'special') return specialTargets?.find(s => s.id === id)?.display_name || id
    return id
  }, [peers, groups, specialTargets])
  const getServiceName = useCallback((id) => services?.find(s => s.id === id)?.name || id, [services])

  // Search state
  const [searchTerm, setSearchTerm] = useState('')

  // Pre-filter by enabled toggle and peer filter before search/sort
  const preFilteredPolicies = policies?.filter(p => {
    if (!showDisabled && !p.enabled) return false
    if (filterPeer && (p.target_type !== 'peer' || p.target_id !== filterPeer)) return false
    return true
  })

  // Processed policies: filter and sort
  const processedPolicies = useTableFilter(preFilteredPolicies, searchTerm, sortConfig, {
    filterFn: (p, term) => {
      const name = (p.name || '').toLowerCase()
      const source = getEntityName(p.source_type, p.source_id).toLowerCase()
      const service = getServiceName(p.service_id).toLowerCase()
      const target = getEntityName(p.target_type, p.target_id).toLowerCase()
      return name.includes(term) || source.includes(term) || service.includes(term) || target.includes(term)
    },
    fieldMap: {
      source: (p) => getEntityName(p.source_type, p.source_id).toLowerCase(),
      service: (p) => getServiceName(p.service_id).toLowerCase(),
      target: (p) => getEntityName(p.target_type, p.target_id).toLowerCase(),
    },
    extraDeps: [getEntityName, getServiceName],
    secondarySortKey: 'name',
  })

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

  // Auto-open New Policy modal when navigating from Dashboard Quick Actions
  useEffect(() => {
    if (location.state?.openAddModal && canEdit) {
      openAdd()
      // Clear the navigation state to prevent re-opening on refresh
      window.history.replaceState({}, document.title)
    }
  }, [location.state, canEdit, openAdd])

  if (isLoading) return <TableSkeleton rows={3} columns={7} />

  return (
    <div className="space-y-4">
      <PageHeader
        title="Policies"
        description="Create firewall rules to control network traffic between groups and peers"
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
            {canEdit && (
              <button onClick={openAdd} className="flex items-center gap-2 px-4 py-2 bg-purple-active hover:bg-purple-active/80 text-white text-sm font-medium rounded-lg">
                <Plus className="w-4 h-4" /> New Policy
              </button>
            )}
          </>
        }
      />

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
              {SYSTEM_RULES.map((rule) => (
                <div key={rule.title} className="flex items-start gap-2">
                  <span
                    className={rule.type === 'accept' ? 'text-green-500 mt-0.5' : 'text-red-500 mt-0.5'}
                    aria-hidden="true"
                  >
                    {rule.type === 'accept' ? '✓' : '✕'}
                  </span>
                  <div>
                    <span className="font-medium text-gray-700 dark:text-amber-primary">{rule.title}:</span>
                    <span className="text-gray-600 dark:text-amber-muted ml-1">{rule.description}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

  {/* Filters */}
  <TableToolbar
    searchTerm={searchTerm}
    onSearchChange={(v) => setSearchTerm(v)}
    onClearSearch={() => setSearchTerm('')}
    placeholder="Search policies by name, source, service, or target..."
    rowsPerPage={policiesRowsPerPage}
    onRowsPerPageChange={setPoliciesRowsPerPage}
  />

  {/* Show Disabled Filter Chips */}
  <div className="flex gap-2">
    {[
      { value: 'enabled', label: 'Enabled' },
      { value: 'disabled', label: 'Disabled' },
    ].map(opt => (
      <button
        key={opt.value}
        onClick={() => setShowDisabled(opt.value === 'disabled')}
        className={`px-3 py-1.5 text-sm font-medium rounded-lg transition-colors ${
          showDisabled === (opt.value === 'disabled')
            ? 'bg-purple-active text-white'
            : 'bg-gray-100 dark:bg-charcoal-darkest text-gray-700 dark:text-amber-primary hover:bg-gray-200 dark:hover:bg-charcoal-dark'
        }`}
      >
        {opt.label}
      </button>
    ))}
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
                        {canEdit && (
                          <button onClick={() => openEdit(p)} className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded" title="Edit">
                            <Pencil className="w-4 h-4 text-gray-500" />
                          </button>
                        )}
                        {canEdit && (
                          <button onClick={() => setDeleteTarget(p)} className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded" title="Delete">
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

          <Pagination showingRange={policiesShowingRange} page={policiesPage} totalPages={totalPages} onPageChange={setPoliciesPage} totalItems={policiesTotal} />
        </div>
      )}

{modalOpen && (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" tabIndex="-1" onKeyDown={(e) => { if (e.key === 'Escape') { closeModal() } }}>
        <div ref={modalRef} className="bg-white dark:bg-charcoal-dark rounded-xl shadow-xl w-full max-w-2xl mx-4 flex flex-col max-h-[90vh]">
          {/* Header */}
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border flex items-center justify-between shrink-0">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">{editPolicy ? 'Edit Policy' : 'New Policy'}</h3>
            <button type="button" onClick={closeModal} className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded">
              <X className="w-5 h-5 text-gray-400" />
            </button>
          </div>
          {/* Tabs */}
          <div className="flex border-b border-gray-200 dark:border-gray-border shrink-0">
            <button type="button" onClick={() => setActiveTab('setup')} className={`flex-1 px-4 py-3 text-sm font-medium transition-colors ${activeTab === 'setup' ? 'text-purple-active border-b-2 border-purple-active' : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'}`}>Setup</button>
            <button type="button" onClick={() => setActiveTab('preview')} className={`flex-1 px-4 py-3 text-sm font-medium transition-colors ${activeTab === 'preview' ? 'text-purple-active border-b-2 border-purple-active' : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'}`}>Preview</button>
          </div>
          {/* Tab Content */}
          <div className="flex-1 overflow-y-auto">
            {activeTab === 'setup' && (
              <form id="policy-form" onSubmit={handleSubmit} className="p-6 space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="col-span-2 sm:col-span-1">
                    <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Name</label>
                    <input autoFocus type="text" value={formData.name} onChange={e => setFormData(d => ({ ...d, name: e.target.value }))} required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-purple-active" />
                  </div>
                  <div className="col-span-2 sm:col-span-1">
                    <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Priority</label>
                    <input type="number" value={formData.priority} onChange={e => setFormData(d => ({ ...d, priority: e.target.value === '' ? '' : parseInt(e.target.value, 10) }))} required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-purple-active" />
                  </div>
                </div>
                {/* Collapsible Description Section */}
                <div className="border border-gray-200 dark:border-gray-border rounded-lg overflow-hidden">
                  <button
                    type="button"
                    onClick={() => setShowDescription(!showDescription)}
                    className="w-full px-4 py-3 flex items-center justify-between bg-gray-50 dark:bg-charcoal-darkest hover:bg-gray-100 dark:hover:bg-charcoal-dark transition-colors"
                  >
                    <span className="text-sm font-medium text-gray-700 dark:text-amber-primary">Description (Optional)</span>
                    <svg className={`w-4 h-4 text-gray-500 transition-transform duration-150 ${showDescription ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </button>
                  <div className={`transition-all duration-150 ease-in-out ${showDescription ? 'max-h-32 opacity-100' : 'max-h-0 opacity-0'} overflow-hidden`}>
                    <div className="p-4">
                      <textarea
                        value={formData.description}
                        onChange={e => setFormData(d => ({ ...d, description: e.target.value }))}
                        rows={2}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white"
                        placeholder="Add a description for this policy..."
                      />
                    </div>
                  </div>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-[1fr_auto_1fr] gap-x-4 gap-y-4 items-end">
                  {/* Row 1: Source - Direction - Target */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Source</label>
                    <div title={isIGMPService ? "IGMP is a host-level protocol — source is not used" : undefined} className={isIGMPService ? 'opacity-50' : ''}>
                      <SearchableSelect options={polymorphicOptions} value={formData.source_id} category={formData.source_type} onChange={(v, type) => setFormData(d => ({ ...d, source_id: v, source_type: type }))} placeholder="Select group or peer" disabled={isIGMPService} />
                    </div>

                  </div>
                  <div className="flex flex-col items-center justify-end gap-1.5 pb-0.5">
                    <div className="flex flex-col gap-1.5">
                      <button
                        type="button"
                        onClick={() => {
                          if (formData.direction === 'forward' || isIGMPService) return
                          setFormData(d => ({
                            ...d,
                            direction: d.direction === 'both' ? 'backward' : (d.direction === 'backward' ? 'both' : 'forward')
                          }))
                        }}
                        disabled={isIGMPService}
                        className={`flex items-center justify-center w-28 h-8 rounded-xl border-2 transition-all duration-200 ${
                          formData.direction === 'both' || formData.direction === 'forward'
                            ? 'bg-emerald-900/80 border-emerald-500 text-emerald-400 hover:bg-emerald-800/80'
                            : 'bg-gray-200 dark:bg-gray-800 border-gray-300 dark:border-gray-600 text-gray-400 dark:text-gray-500 hover:bg-gray-300 dark:hover:bg-gray-700'
                        } ${isIGMPService ? 'opacity-50 cursor-not-allowed' : ''}`}
                        title={isIGMPService ? "IGMP generates both INPUT and OUTPUT automatically — direction is fixed" : "Forward: Source → Target"}
                      >
                        <svg viewBox="0 0 80 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="w-16 h-4">
                          <line x1="8" y1="12" x2="66" y2="12" />
                          <polyline points="58,6 66,12 58,18" />
                        </svg>
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          if (formData.direction === 'backward' || isIGMPService) return
                          setFormData(d => ({
                            ...d,
                            direction: d.direction === 'both' ? 'forward' : (d.direction === 'forward' ? 'both' : 'backward')
                          }))
                        }}
                        disabled={isIGMPService}
                        className={`flex items-center justify-center w-28 h-8 rounded-xl border-2 transition-all duration-200 ${
                          formData.direction === 'both' || formData.direction === 'backward'
                            ? 'bg-emerald-900/80 border-emerald-500 text-emerald-400 hover:bg-emerald-800/80'
                            : 'bg-gray-200 dark:bg-gray-800 border-gray-300 dark:border-gray-600 text-gray-400 dark:text-gray-500 hover:bg-gray-300 dark:hover:bg-gray-700'
                        } ${isIGMPService ? 'opacity-50 cursor-not-allowed' : ''}`}
                        title={isIGMPService ? "IGMP generates both INPUT and OUTPUT automatically — direction is fixed" : "Backward: Target → Source"}
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
      {/* Docker Integration Scope - Only shown when target is a peer and has Docker */}
      {selectedPeerHasDocker && (
        <div>
          <div className="flex items-center gap-2 mb-1">
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary">Applies To</label>
            <span className="text-xs text-gray-500 dark:text-amber-muted">(Docker Integration)</span>
            {isIGMPService && <span className="text-xs text-blue-600 dark:text-blue-400 ml-1">— "Host Only" is typical for IGMP</span>}
          </div>
          <div className="flex bg-gray-100 dark:bg-charcoal-darkest p-1 rounded-lg border border-gray-200 dark:border-gray-border">
            <button
              type="button"
              onClick={() => setFormData(d => ({ ...d, target_scope: 'both' }))}
              className={`flex-1 py-1.5 text-xs font-medium rounded-md transition-all duration-200 ${
                formData.target_scope === 'both' || !formData.target_scope
                  ? 'bg-white dark:bg-charcoal-dark text-gray-900 dark:text-white shadow-sm ring-1 ring-black/5 dark:ring-white/10'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-white/50 dark:hover:bg-charcoal-dark/50'
              }`}
            >
              Host + Docker
            </button>
            <button
              type="button"
              onClick={() => setFormData(d => ({ ...d, target_scope: 'host' }))}
              className={`flex-1 py-1.5 text-xs font-medium rounded-md transition-all duration-200 ${
                formData.target_scope === 'host'
                  ? 'bg-white dark:bg-charcoal-dark text-gray-900 dark:text-white shadow-sm ring-1 ring-black/5 dark:ring-white/10'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-white/50 dark:hover:bg-charcoal-dark/50'
              }`}
            >
              Host Only
            </button>
            <button
              type="button"
              onClick={() => setFormData(d => ({ ...d, target_scope: 'docker' }))}
              className={`flex-1 py-1.5 text-xs font-medium rounded-md transition-all duration-200 ${
                formData.target_scope === 'docker'
                  ? 'bg-white dark:bg-charcoal-dark text-gray-900 dark:text-white shadow-sm ring-1 ring-black/5 dark:ring-white/10'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-white/50 dark:hover:bg-charcoal-dark/50'
              }`}
            >
              Docker Only
            </button>
          </div>
        </div>
      )}

      {/* Policy Enabled Section */}
      <div className="p-4 bg-gray-50 dark:bg-charcoal-darkest border border-gray-200 dark:border-gray-border rounded-lg">
        <div className="flex items-center justify-between">
          <div>
            <label className="text-sm font-medium text-gray-900 dark:text-light-neutral">Policy enabled</label>
            <p className="text-xs text-gray-500 dark:text-amber-muted mt-0.5">When disabled, this policy will not generate any firewall rules until re-enabled.</p>
          </div>
          <ToggleSwitch checked={formData.enabled} onChange={v => setFormData(d => ({ ...d, enabled: v }))} />
        </div>
      </div>

                <InlineError message={formErrors._general} />
              </form>
            )}
            {activeTab === 'preview' && (
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="text-sm font-medium text-gray-700 dark:text-amber-primary">Generated Rules</h4>
                  <button type="button" onClick={fetchPreview} disabled={previewLoading} className="flex items-center gap-2 text-sm text-purple-active hover:opacity-80">
                    <RefreshCw className={`w-4 h-4 ${previewLoading ? 'animate-spin' : ''}`} />
                    Refresh
                  </button>
                </div>
                {previewLoading && !preview && (
                  <div className="flex items-center justify-center py-8">
                    <RefreshCw className="w-6 h-6 animate-spin text-purple-active" />
                    <span className="ml-2 text-sm text-gray-500">Generating preview...</span>
                  </div>
                )}
                {preview && (
                  <div className="p-3 bg-gray-900 dark:bg-charcoal-darkest rounded-lg text-xs font-mono border border-gray-800 max-h-96 overflow-y-auto">
                    {preview.rules?.map((rule, i) => (
                      <p key={i} className="text-green-400 whitespace-pre-wrap">{rule}</p>
                    ))}
                    {!preview.rules?.length && <p className="text-gray-500 italic">No rules generated for this orientation.</p>}
                  </div>
                )}
                {!previewLoading && !preview && (
                  <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                    <Eye className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">Select source, service, and target to preview rules</p>
                  </div>
                )}
              </div>
            )}
          </div>
          {/* Footer */}
          <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-border flex justify-end gap-3 shrink-0 bg-white dark:bg-charcoal-dark rounded-b-xl">
            <button type="button" onClick={closeModal} className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-lg hover:bg-gray-50 dark:hover:bg-charcoal-darkest">Cancel</button>
            <button type="submit" form="policy-form" disabled={activeTab !== 'setup'} className="px-4 py-2 text-sm font-medium text-white bg-purple-active hover:bg-purple-active/80 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed">{editPolicy ? 'Save Changes' : 'Create Policy'}</button>
          </div>
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
