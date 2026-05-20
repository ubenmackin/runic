import { useState, useCallback, useRef, useEffect, useMemo } from 'react'
import { useLocation } from 'react-router-dom'
import { useFilterPersistence } from '../hooks/useFilterPersistence'
import { useTableSort } from '../hooks/useTableSort'
import { usePagination } from '../hooks/usePagination'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, RefreshCw, ChevronDown, ChevronUp, Info } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useCrudModal } from '../hooks/useCrudModal'
import { useToastContext } from '../hooks/ToastContext'
import { useTableFilter } from '../hooks/useTableFilter'
import { useCrudMutations } from '../hooks/useCrudMutations'
import { useAuth } from '../hooks/useAuth'
import ConfirmModal from '../components/ConfirmModal'
import TableSkeleton from '../components/TableSkeleton'
import SearchFilterPanel from '../components/SearchFilterPanel'
import FilterChip from '../components/FilterChip'
import PageHeader from '../components/PageHeader'
import PolicyTable from '../components/PolicyTable'
import PolicyFormModal from '../components/PolicyFormModal'
import { parseCompositePeerValue } from '../utils/peerUtils'

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
  { type: 'deny', title: 'Default Deny + Logging', description: 'All unmatched INPUT traffic is logged with prefix "[RUNIC-DROP-I]" and OUTPUT traffic with "[RUNIC-DROP-O]", then dropped.' },
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
    source_ip: '',
    service_id: '',
    target_id: '',
    target_type: 'peer',
    target_ip: '',
    action: 'ACCEPT',
    priority: 100,
    enabled: true,
    target_scope: 'both',
    direction: 'both'
  })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const { value: showDisabled, setValue: setShowDisabled } = useFilterPersistence('policies', 'showDisabled', false)
  const [preview, setPreview] = useState(null)
  const [previewStale, setPreviewStale] = useState(false)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [formErrors, setFormErrors] = useState({})
  const [activeTab, setActiveTab] = useState('setup')
  const [showSystemRules, setShowSystemRules] = useState(false)
  const [showDescription, setShowDescription] = useState(false)

  const [showPendingDeletes, setShowPendingDeletes] = useState(false)

  const { sortConfig, handleSort } = useTableSort('policies', { key: 'priority', direction: 'asc' })

  const [isManualRefreshing, setIsManualRefreshing] = useState(false)

  const openAdd = useCallback(() => {
    setFormErrors({})
    setPreview(null)
    setPreviewStale(false)
    setActiveTab('setup')
    setShowDescription(false)
    handleOpenAdd()
  }, [handleOpenAdd])
  const openEdit = (p) => {
    setEditPolicy(p);
    // Build composite source/target values for multi-IP peers.
    // For multi-IP peers, use composite value like "peer:5:10.20.10.20"
    // so the SearchableSelect can find the matching option in the dropdown.
    // For single-IP peers, use plain numeric ID and keep source_ip/target_ip separate.
    const sourcePeer = p.source_type === 'peer' ? peers?.find(pr => pr.id === p.source_id) : null
    const targetPeer = p.target_type === 'peer' ? peers?.find(pr => pr.id === p.target_id) : null
    const isSourceMultiIP = sourcePeer && sourcePeer.ips && sourcePeer.ips.length > 1
    const isTargetMultiIP = targetPeer && targetPeer.ips && targetPeer.ips.length > 1
    setFormForEdit({
      ...p,
      source_id: isSourceMultiIP && p.source_ip
        ? `peer:${p.source_id}:${p.source_ip}`
        : p.source_id,
      target_id: isTargetMultiIP && p.target_ip
        ? `peer:${p.target_id}:${p.target_ip}`
        : p.target_id,
    });
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

  const isIGMPService = formData.service_id && services?.find(s => s.id === formData.service_id)?.name?.toUpperCase() === 'IGMP'

  const isVRRPService = formData.service_id && services?.find(s => s.id === formData.service_id)?.name?.toUpperCase() === 'VRRP'

  const isSpecialService = isIGMPService || isVRRPService



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
    // Parse composite peer values to extract plain IDs and IP addresses
    let submitData = { ...formData }
    // Handle source_id - check for composite value first
    const sourceParsed = parseCompositePeerValue(formData.source_id)
    if (sourceParsed) {
      submitData.source_id = sourceParsed.id
      submitData.source_ip = sourceParsed.ip || ''
    } else {
      // Plain numeric ID — preserve existing source_ip from form (set during edit)
      submitData.source_ip = formData.source_type === 'peer' ? (formData.source_ip || '') : ''
    }
    // Handle target_id - check for composite value first
    const targetParsed = parseCompositePeerValue(formData.target_id)
    if (targetParsed) {
      submitData.target_id = targetParsed.id
      submitData.target_ip = targetParsed.ip || ''
    } else {
      // Plain numeric ID — preserve existing target_ip from form (set during edit)
      submitData.target_ip = formData.target_type === 'peer' ? (formData.target_ip || '') : ''
    }
    if (editPolicy) updateMutation.mutate({ id: editPolicy.id, data: submitData })
    else createMutation.mutate(submitData)
  }

  const fetchPreview = useCallback(async () => {
    // IGMP and VRRP don't require source_id
    if (!formData.service_id || !formData.target_id || (!isSpecialService && !formData.source_id)) {
      setFormErrors({ _general: isSpecialService ? 'Select service and target to preview' : 'Select source, service, and target to preview' })
      return
    }
    // Parse composite peer values for preview
    const sourceParsed = parseCompositePeerValue(formData.source_id)
    const targetParsed = parseCompositePeerValue(formData.target_id)
    const previewSourceId = sourceParsed ? sourceParsed.id : formData.source_id
    const previewSourceType = sourceParsed ? 'peer' : formData.source_type
    const previewSourceIp = sourceParsed
      ? sourceParsed.ip
      : (formData.source_type === 'peer' ? (formData.source_ip || '') : '')
    const previewTargetId = targetParsed ? targetParsed.id : formData.target_id
    const previewTargetType = targetParsed ? 'peer' : formData.target_type
    const previewTargetIp = targetParsed
      ? targetParsed.ip
      : (formData.target_type === 'peer' ? (formData.target_ip || '') : '')
    setPreviewLoading(true)
    try {
      const data = await api.post('/policies/preview', {
        source_id: previewSourceId,
        source_type: previewSourceType,
        source_ip: previewSourceIp || undefined,
        service_id: formData.service_id,
        target_id: previewTargetId,
        target_type: previewTargetType,
        target_ip: previewTargetIp || undefined,
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
  }, [formData, isSpecialService])

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

  // Auto-set source to "All Hosts (IGMP)" when IGMP/VRRP service is selected
  useEffect(() => {
    if (modalOpen && isSpecialService && !formData.source_id) {
      setFormData(d => ({ ...d, source_id: SPECIAL_TARGETS.ALL_HOSTS.id, source_type: 'special', source_ip: '' }))
    }
  }, [modalOpen, isSpecialService, formData.source_id, setFormData])

  const getEntityName = useCallback((type, id, ip) => {
    if (type === 'peer') {
      const peer = peers?.find(p => p.id === id)
      const hostname = peer?.hostname || id
      if (ip) return `${hostname} (${ip})`
      return hostname
    }
    if (type === 'group') return groups?.find(g => g.id === id)?.name || id
    if (type === 'special') return specialTargets?.find(s => s.id === id)?.display_name || id
    return id
  }, [peers, groups, specialTargets])
  const getServiceName = useCallback((id) => services?.find(s => s.id === id)?.name || id, [services])

  const [searchTerm, setSearchTerm] = useState('')

  const preFilteredPolicies = (policies || []).filter(p => {
    if (!showDisabled && !p.enabled) return false
    // Filter by pending delete status
    if (!showPendingDeletes && p.is_pending_delete) return false
    return true
  })

  const processedPolicies = useTableFilter(preFilteredPolicies, searchTerm, sortConfig, {
    filterFn: (p, term) => {
      const name = (p.name || '').toLowerCase()
      const source = getEntityName(p.source_type, p.source_id, p.source_ip).toLowerCase()
      const service = getServiceName(p.service_id).toLowerCase()
      const target = getEntityName(p.target_type, p.target_id, p.target_ip).toLowerCase()
      return name.includes(term) || source.includes(term) || service.includes(term) || target.includes(term)
    },
    fieldMap: {
      source: (p) => getEntityName(p.source_type, p.source_id, p.source_ip).toLowerCase(),
      service: (p) => getServiceName(p.service_id).toLowerCase(),
      target: (p) => getEntityName(p.target_type, p.target_id, p.target_ip).toLowerCase(),
    },
    extraDeps: [getEntityName, getServiceName],
    secondarySortKey: 'name',
  })

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

  useEffect(() => {
    setPoliciesPage(1)
  }, [searchTerm, setPoliciesPage])

  // Auto-open New Policy modal when navigating from Dashboard Quick Actions
  useEffect(() => {
    if (location.state?.openAddModal && canEdit) {
      openAdd()
      // Clear the navigation state to prevent re-opening on refresh
      window.history.replaceState({}, document.title)
    }
  }, [location.state, canEdit, openAdd])

  // Filter chips for enabled/disabled toggle - must be above early returns for hooks rules
  const enabledFilterChips = useMemo(() => [
    { value: 'enabled', label: 'Enabled' },
    { value: 'disabled', label: 'Disabled' },
  ].map(opt => (
    <FilterChip
      key={opt.value}
      label={opt.label}
      selected={showDisabled === (opt.value === 'disabled')}
      onClick={() => setShowDisabled(opt.value === 'disabled')}
    />

  )), [showDisabled, setShowDisabled])

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
              className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-none hover:bg-gray-50 dark:hover:bg-charcoal-darkest disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${isManualRefreshing ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            {canEdit && (
              <button onClick={openAdd} className="flex items-center gap-2 px-4 py-2 bg-purple-active hover:bg-purple-600 text-white text-sm font-bold uppercase rounded-none border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all">
                <Plus className="w-4 h-4" /> New Policy
              </button>
            )}
          </>
        }
      />

      <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none overflow-hidden">
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

      <SearchFilterPanel
        storageKey="policies-search-filters-expanded"
        searchTerm={searchTerm}
        onSearchChange={setSearchTerm}
        onClearSearch={() => setSearchTerm('')}
        searchPlaceholder="Search policies by name, source, service, or target..."
        rowsPerPage={policiesRowsPerPage}
        onRowsPerPageChange={setPoliciesRowsPerPage}
        filterChips={enabledFilterChips}
      >
        {policies?.some(p => p.is_pending_delete) && (
          <div className="flex items-center gap-2 px-1">
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
      </SearchFilterPanel>

<PolicyTable
  policies={policies}
  paginatedPolicies={paginatedPolicies}
  sortConfig={sortConfig}
  onSort={handleSort}
  onEdit={openEdit}
  onDelete={(p) => setDeleteTarget(p)}
  canEdit={canEdit}
  searchTerm={searchTerm}
  showPendingDeletes={showPendingDeletes}
  setShowPendingDeletes={setShowPendingDeletes}
  toggleMutation={toggleMutation}
  getEntityName={getEntityName}
  getServiceName={getServiceName}
  openAdd={openAdd}
  showingRange={policiesShowingRange}
  page={policiesPage}
  totalPages={totalPages}
  onPageChange={setPoliciesPage}
  totalItems={policiesTotal}
/>

<PolicyFormModal
  isOpen={modalOpen}
  onClose={closeModal}
  editItem={editPolicy}
  peerList={peers}
  serviceList={services}
  groupList={groups}
  specialTargetList={specialTargets}
  formData={formData}
  setFormData={setFormData}
  formErrors={formErrors}
  setFormErrors={setFormErrors}
  activeTab={activeTab}
  setActiveTab={setActiveTab}
  showDescription={showDescription}
  setShowDescription={setShowDescription}
  preview={preview}
  previewStale={previewStale}
  previewLoading={previewLoading}
  onSubmit={handleSubmit}
  onPreview={fetchPreview}
/>

      {deleteTarget && (
        <ConfirmModal
          title="Delete Policy"
          message={`Delete policy "${deleteTarget.name}"? Rules will be removed from ${getEntityName(deleteTarget.target_type, deleteTarget.target_id, deleteTarget.target_ip)} on next push.`}
          onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
          onCancel={() => setDeleteTarget(null)}
          danger
        />
      )}
    </div>
  )
}
