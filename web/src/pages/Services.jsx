import { useState, useCallback, useRef, useEffect } from 'react'
import { useTableSort } from '../hooks/useTableSort'
import { usePagination } from '../hooks/usePagination'
import { useQuery } from '@tanstack/react-query'
import { Plus, Pencil, Trash2, RefreshCw, X, Package, ChevronDown, ChevronUp } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useCrudModal } from '../hooks/useCrudModal'
import { useToastContext } from '../hooks/ToastContext'
import { useFocusTrap } from '../hooks/useFocusTrap'
import { useTableFilter } from '../hooks/useTableFilter'
import { useCrudMutations } from '../hooks/useCrudMutations'
import { useAuth } from '../hooks/useAuth'
import ConfirmModal from '../components/ConfirmModal'
import InlineError from '../components/InlineError'
import EmptyState from '../components/EmptyState'
import TableSkeleton from '../components/TableSkeleton'
import SearchableSelect from '../components/SearchableSelect'
import SortIndicator from '../components/SortIndicator'
import Pagination from '../components/Pagination'
import SearchFilterPanel from '../components/SearchFilterPanel'
import PageHeader from '../components/PageHeader'
import SharpTag from '../components/SharpTag'

const PROTOCOL_OPTIONS = [
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
  { value: 'both', label: 'TCP+UDP' },
  { value: 'icmp', label: 'ICMP' },
  { value: 'igmp', label: 'IGMP' }
]

// Protocol options for user-created services (excludes ICMP which is system-only)
const USER_PROTOCOL_OPTIONS = [
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
  { value: 'both', label: 'TCP+UDP' },
]

export default function Services() {
  const showToast = useToastContext()
  const { canEdit } = useAuth()
  const { modalOpen, setModalOpen, editItem: editService, setEditItem: setEditService, form: formData, setForm: setFormData, setFormForEdit, handleOpenAdd, handleCancel: closeModal } = useCrudModal({ name: '', protocol: 'tcp', ports: '', source_ports: '', description: '' })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [conflictError, setConflictError] = useState(null)
  const [formErrors, setFormErrors] = useState({})
  const [portChips, setPortChips] = useState([])
  const [portInput, setPortInput] = useState('')
  const [portInputError, setPortInputError] = useState('')
  const [sourcePortChips, setSourcePortChips] = useState([])
  const [sourcePortInput, setSourcePortInput] = useState('')
  const [sourcePortInputError, setSourcePortInputError] = useState('')
  const [showSourcePorts, setShowSourcePorts] = useState(false)
  const [showDescription, setShowDescription] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const [showSystemServices, setShowSystemServices] = useState(false)

  // Toggle for showing pending deletes
  const [showPendingDeletes, setShowPendingDeletes] = useState(false)

  // Sorting state (persisted per-user)
  const { sortConfig, handleSort } = useTableSort('services', { key: 'name', direction: 'asc' })

  // Manual refresh state
  const [isManualRefreshing, setIsManualRefreshing] = useState(false)

  // Modal ref for focus trap
  const modalRef = useRef(null)

  // Focus trap for modal accessibility
  useFocusTrap(modalRef, modalOpen)

  const openAdd = () => { setFormErrors({}); setPortChips([]); setPortInput(''); setPortInputError(''); setSourcePortChips([]); setSourcePortInput(''); setSourcePortInputError(''); setShowSourcePorts(false); setShowDescription(false); handleOpenAdd() }
  const openEdit = (s) => {
    setEditService(s);
    setFormForEdit(s);
    setFormErrors({});
    // Initialize port chips from existing ports
    const ports = s.ports ? s.ports.split(',').map(p => p.trim()).filter(Boolean) : []
    setPortChips(ports)
    setPortInput('')
    setPortInputError('')
    // Initialize source port chips from existing source_ports
    const sourcePorts = s.source_ports ? s.source_ports.split(',').map(p => p.trim()).filter(Boolean) : []
    setSourcePortChips(sourcePorts)
    setSourcePortInput('')
    setSourcePortInputError('')
    setShowSourcePorts(sourcePorts.length > 0)
    setShowDescription(!!s.description)
    setModalOpen(true)
  }

  const { data: services, isLoading, refetch } = useQuery({
    queryKey: QUERY_KEYS.services(),
    queryFn: () => api.get('/services'),
  })

  // Manual refresh handler
  const handleManualRefresh = useCallback(async () => {
    setIsManualRefreshing(true)
    await refetch()
    setIsManualRefreshing(false)
  }, [refetch])

  // Split services into system and user services
  const systemServices = services?.filter(s => s.is_system) || []
  const userServices = services?.filter(s => !s.is_system) || []

  // Filter soft-deleted items based on toggle
  const visibleServices = showPendingDeletes ? userServices : userServices.filter(s => !s.is_pending_delete)

  const processedServices = useTableFilter(visibleServices, searchTerm, sortConfig, {
    filterFn: (s, term) => {
      const name = (s.name || '').toLowerCase()
      const protocol = (s.protocol || '').toLowerCase()
      const ports = (s.ports || '').toLowerCase()
      const description = (s.description || '').toLowerCase()
      return name.includes(term) || protocol.includes(term) || ports.includes(term) || description.includes(term)
    },
    fieldMap: {
      ports: (s) => parseInt((s.ports || '0').split(',')[0].split(':')[0]) || 0,
    },
    secondarySortKey: 'name',
  })

  // Pagination state
  const {
    paginatedData: paginatedServices,
    totalPages,
    showingRange: servicesShowingRange,
    page: servicesPage,
    rowsPerPage: servicesRowsPerPage,
    onPageChange: setServicesPage,
    onRowsPerPageChange: setServicesRowsPerPage,
    totalItems: servicesTotal
  } = usePagination(processedServices, 'services')

  // Reset page to 1 when search term changes
  useEffect(() => {
    setServicesPage(1)
  }, [searchTerm, setServicesPage])

  const { createMutation, updateMutation, deleteMutation } = useCrudMutations({
    apiPath: '/services',
    queryKey: QUERY_KEYS.services(),
    additionalInvalidations: [['pending-changes']],
    onCreateSuccess: closeModal,
    onUpdateSuccess: closeModal,
    onDeleteSuccess: () => setDeleteTarget(null),
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
          serviceName: deleteTarget.name,
          policies: err.data.policies,
        })
        setDeleteTarget(null)
      }
      // Other errors are already handled by the mutation's onError
    }
  }

  // Validate a single port or range
  const validatePortEntry = (entry) => {
    const trimmed = entry.trim()
    if (!trimmed) return false

    // Must match backend regex: only digits, commas, and colons
    // Pattern: ^\d+([,:]\d+)*$
    if (!/^\d+([,:]\d+)*$/.test(trimmed)) {
      return false
    }

    // Validate each port number is in valid range
    const parts = trimmed.split(/[,:]/)
    for (const part of parts) {
      const port = parseInt(part)
      if (isNaN(port) || port < 1 || port > 65535) {
        return false
      }
    }

    // Validate ranges (colon-separated pairs) have start <= end
    const rangeMatch = trimmed.match(/(\d+):(\d+)/g)
    if (rangeMatch) {
      for (const range of rangeMatch) {
        const [start, end] = range.split(':').map(Number)
        if (start > end) return false
      }
    }

    return true
  }

  // Add port chip
  const handleAddPort = () => {
    const input = portInput.trim()
    if (!input) {
      setPortInputError('Please enter a port or range')
      return
    }

    // Split by comma and validate each
    const entries = input.split(',').map(e => e.trim()).filter(Boolean)
    const invalidEntries = entries.filter(e => !validatePortEntry(e))

    if (invalidEntries.length > 0) {
      setPortInputError(`Invalid port(s): ${invalidEntries.join(', ')}. Only digits, commas, and colons allowed. Port range: 1-65535`)
      return
    }

    // Check for duplicates
    const duplicates = entries.filter(e => portChips.includes(e))
    if (duplicates.length > 0) {
      setPortInputError(`Already added: ${duplicates.join(', ')}`)
      return
    }

    setPortChips([...portChips, ...entries])
    setPortInput('')
    setPortInputError('')
  }

// Remove port chip
const handleRemovePort = (port) => {
  setPortChips(portChips.filter(p => p !== port))
}

// Handle Enter key in port input
const handlePortInputKeyDown = (e) => {
  if (e.key === 'Enter') {
    e.preventDefault()
    handleAddPort()
  }
}

// Add source port chip
const handleAddSourcePort = () => {
  const input = sourcePortInput.trim()
  if (!input) {
    setSourcePortInputError('Please enter a port or range')
    return
  }

  // Split by comma and validate each
  const entries = input.split(',').map(e => e.trim()).filter(Boolean)
  const invalidEntries = entries.filter(e => !validatePortEntry(e))

  if (invalidEntries.length > 0) {
    setSourcePortInputError(`Invalid port(s): ${invalidEntries.join(', ')}. Only digits, commas, and colons allowed. Port range: 1-65535`)
    return
  }

  // Check for duplicates
  const duplicates = entries.filter(e => sourcePortChips.includes(e))
  if (duplicates.length > 0) {
    setSourcePortInputError(`Already added: ${duplicates.join(', ')}`)
    return
  }

  setSourcePortChips([...sourcePortChips, ...entries])
  setSourcePortInput('')
  setSourcePortInputError('')
}

// Remove source port chip
const handleRemoveSourcePort = (port) => {
  setSourcePortChips(sourcePortChips.filter(p => p !== port))
}

// Handle Enter key in source port input
const handleSourcePortInputKeyDown = (e) => {
  if (e.key === 'Enter') {
    e.preventDefault()
    handleAddSourcePort()
  }
}

  const handleSubmit = (e) => {
    e.preventDefault()

    // Clear previous errors
    setFormErrors({})

    // Join port chips into comma-separated string for API
    const portsValue = portChips.join(',')
    const sourcePortsValue = sourcePortChips.join(',')

    // Validate: non-ICMP/IGMP protocols require at least one port type
    if (formData.protocol !== 'icmp' && formData.protocol !== 'igmp' && !portsValue && !sourcePortsValue) {
      setFormErrors({ _general: 'At least one destination port or source port is required for TCP/UDP protocols' })
      return
    }

    const submitData = { ...formData, ports: portsValue, source_ports: sourcePortsValue }
    if (editService) updateMutation.mutate({ id: editService.id, data: submitData })
    else createMutation.mutate(submitData)
  }

  const protocolLabel = (p) => ({ tcp: 'TCP', udp: 'UDP', both: 'TCP+UDP', icmp: 'ICMP', igmp: 'IGMP' }[p] || p)

  if (isLoading) return <TableSkeleton rows={3} columns={5} />

 return (
 <div className="space-y-4">
      <PageHeader
        title="Services"
        description="Define port and protocol bundles to simplify policy creation"
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
                <Plus className="w-4 h-4" /> New Service
              </button>
            )}
          </>
        }
      />

      {/* System Services Collapsible Panel */}
      {systemServices.length > 0 && (
        <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none overflow-hidden">
          <button
            type="button"
            onClick={() => setShowSystemServices(!showSystemServices)}
            className="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-gray-50 dark:hover:bg-charcoal-darkest transition-colors"
          >
            <div className="flex items-center gap-2">
              <Package className="w-5 h-5 text-purple-active" />
              <span className="font-medium text-gray-900 dark:text-light-neutral">System Services</span>
              <span className="text-xs text-gray-500 dark:text-amber-muted">(Automatically managed)</span>
            </div>
            {showSystemServices ? (
              <ChevronUp className="w-5 h-5 text-gray-500" />
            ) : (
              <ChevronDown className="w-5 h-5 text-gray-500" />
            )}
          </button>
          {showSystemServices && (
            <div className="px-4 pb-4 border-t border-gray-200 dark:border-gray-border">
              <div className="mt-3 space-y-1 text-sm">
                {systemServices.map((svc) => (
                  <div key={svc.id} className="p-2 border-b border-gray-100 dark:border-gray-border last:border-b-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium text-gray-900 dark:text-light-neutral">{svc.name}</span>
                      <span className="text-xs px-1.5 py-0.5 rounded bg-gray-100 dark:bg-charcoal-darkest text-gray-600 dark:text-amber-muted">
                        {svc.protocol.toUpperCase()}{svc.ports ? ` :${svc.ports}` : ''}
                      </span>
                      {svc.no_conntrack && (
                        <span className="text-xs text-gray-500 dark:text-amber-muted">No conntrack</span>
                      )}
                    </div>
                    <p className="text-xs text-gray-600 dark:text-amber-muted mt-1">{svc.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

		{/* Search Bar and Rows per page */}
		<SearchFilterPanel
			storageKey="services-search-filters-expanded"
			searchTerm={searchTerm}
			onSearchChange={setSearchTerm}
			onClearSearch={() => setSearchTerm('')}
			searchPlaceholder="Search services..."
			rowsPerPage={servicesRowsPerPage}
			onRowsPerPageChange={setServicesRowsPerPage}
		>
			{/* Show Pending Deletes Toggle */}
			{userServices?.some(s => s.is_pending_delete) && (
				<div className="flex items-center gap-2">
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



      {!processedServices?.length ? (
        searchTerm ? (
          <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none p-8 text-center">
            <p className="text-gray-500 dark:text-amber-muted">No user services match your search.</p>
          </div>
        ) : (
          <EmptyState title="No user services yet" message="Create services to define port bundles for your policies." action="New Service" onAction={openAdd} />
        )
) : (
<div className="bg-white dark:bg-charcoal-dark border border-gray-200 dark:border-gray-border overflow-hidden">
<div className="overflow-x-auto">
            <table className="w-full text-sm">
<thead className="bg-gray-50 dark:bg-charcoal-darkest border-b border-gray-200 dark:border-gray-border">
              <tr>
                <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                  <button type="button" onClick={() => handleSort('name')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                    Name <SortIndicator columnKey="name" sortConfig={sortConfig} />
                  </button>
                </th>
                <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                  <button type="button" onClick={() => handleSort('protocol')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                    Protocol <SortIndicator columnKey="protocol" sortConfig={sortConfig} />
                  </button>
                </th>
                <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                  <button type="button" onClick={() => handleSort('ports')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                    Dest Ports <SortIndicator columnKey="ports" sortConfig={sortConfig} />
                  </button>
                </th>
                <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                  <button type="button" onClick={() => handleSort('description')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                    Description <SortIndicator columnKey="description" sortConfig={sortConfig} />
                  </button>
                </th>
                <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
<tbody className="divide-y divide-gray-200 dark:divide-gray-border">
              {paginatedServices.map((service) => (
<tr key={service.id} className="">
<td className="px-4 py-1">
<span className="font-medium text-gray-900 dark:text-light-neutral">
{service.name}
{service.is_pending_delete && (
<span className="ml-2 px-2 py-1 text-xs bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300 rounded-none">
Pending Delete
</span>
)}
</span>
</td>
<td className="px-4 py-1 text-gray-600 dark:text-amber-primary">
{protocolLabel(service.protocol)}
</td>
<td className="px-4 py-1">
{service.ports ? (
<div className="flex flex-wrap items-center gap-1.5 max-w-xs">
{(() => {
const ports = service.ports.split(',').map(p => p.trim()).filter(Boolean)
const maxVisible = 2
const visiblePorts = ports.slice(0, maxVisible)
const remainingCount = ports.length - maxVisible

return (
<>
              {visiblePorts.map((port, idx) => (
<SharpTag
                                                              key={idx}
                                                              status="info"
                                                              label={port}
                                                              variant="badge"
                                                              color="border-purple-500 text-purple-700 dark:text-purple-400 bg-purple-50 dark:bg-purple-900/20"
                                                            />
              ))}
{remainingCount > 0 && (
<span
className="px-2 py-0.5 text-xs font-mono bg-gray-100 dark:bg-charcoal-darkest text-gray-600 dark:text-amber-muted whitespace-nowrap"
title={ports.slice(maxVisible).join(', ')}
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
<td className="px-4 py-1 text-gray-600 dark:text-amber-primary">
{service.description || '—'}
</td>
<td className="px-4 py-1">
					<div className="flex items-center gap-2">
						{canEdit && (
							<button
								onClick={(e) => { e.stopPropagation(); openEdit(service) }}
								className={`p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none ${(service.is_system || service.is_pending_delete) ? 'text-gray-400 cursor-not-allowed opacity-50' : ''}`}
								disabled={service.is_system || service.is_pending_delete}
								title={service.is_pending_delete ? "Cannot edit soft-deleted services" : service.is_system ? "System services cannot be edited" : "Edit"}
							>
								<Pencil className={`w-4 h-4 ${(service.is_system || service.is_pending_delete) ? 'text-gray-400' : 'text-gray-900 dark:text-white'}`} />
							</button>
						)}
						{canEdit && (
							<button
								onClick={(e) => { e.stopPropagation(); !service.is_system && !service.is_pending_delete && setDeleteTarget(service) }}
								disabled={service.is_system || service.is_pending_delete}
								className={`p-1.5 rounded-none ${(service.is_system || service.is_pending_delete) ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-100 dark:hover:bg-charcoal-darkest'}`}
								title={service.is_pending_delete ? "Cannot delete soft-deleted services" : service.is_system ? "System services cannot be deleted" : "Delete"}
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

          <Pagination showingRange={servicesShowingRange} page={servicesPage} totalPages={totalPages} onPageChange={setServicesPage} totalItems={servicesTotal} />
        </div>
      )}

{modalOpen && (
<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" tabIndex="-1" onKeyDown={(e) => { if (e.key === 'Escape') { closeModal() } }}>
<div
ref={modalRef}
role="dialog"
aria-modal="true"
className="bg-white dark:bg-charcoal-dark rounded-none shadow-none w-full max-w-lg mx-4 flex flex-col max-h-[85vh]"
tabIndex="-1"
>
{/* Fixed Header */}
<div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border flex items-center justify-between shrink-0">
<h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">{editService ? 'Edit Service' : 'New Service'}</h3>
<button onClick={closeModal} className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none">
<X className="w-5 h-5 text-gray-500" />
</button>
</div>
{/* Scrollable Form Content */}
<form id="service-form" onSubmit={handleSubmit} className="p-6 space-y-4 overflow-y-auto flex-1">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Name</label>
                <input type="text" value={formData.name} onChange={e => setFormData(d => ({ ...d, name: e.target.value }))} required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Protocol</label>
                <SearchableSelect
                  options={editService?.is_system ? PROTOCOL_OPTIONS : USER_PROTOCOL_OPTIONS}
                  value={formData.protocol}
                  onChange={(val) => setFormData(d => ({ ...d, protocol: val }))}
                  placeholder="Select protocol..."
                />
                <p className="text-xs text-gray-500 dark:text-amber-muted mt-1">Allow only specified network protocols.</p>
              </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Destination Ports</label>
          <p className="text-xs text-gray-500 dark:text-amber-muted mb-2">Allow network traffic and access only to specified ports. Select ports or port ranges between 1 and 65535.</p>

          {/* Destination port chips display */}
          {portChips.length > 0 && (
            <div className="flex flex-wrap gap-2 mb-2">
              {portChips.map((port, idx) => (
                <span
                  key={idx}
className="px-2 py-1 bg-gray-100 dark:bg-charcoal-darkest rounded-none text-sm flex items-center gap-1 text-gray-900 dark:text-white"
                >
                  {port}
                  <X
                    className="w-3 h-3 text-gray-500 hover:text-red-500 cursor-pointer"
                    onClick={() => handleRemovePort(port)}
                  />
                </span>
              ))}
            </div>
          )}

          {/* Destination port input */}
          <div className="flex gap-2">
            <input
              type="text"
              value={portInput}
              onChange={e => { setPortInput(e.target.value); setPortInputError('') }}
              onKeyDown={handlePortInputKeyDown}
              disabled={formData.protocol === 'icmp' || formData.protocol === 'igmp'}
              placeholder={formData.protocol === 'icmp' ? 'N/A for ICMP' : formData.protocol === 'igmp' ? 'N/A for IGMP' : '22 or 80,443 or 8000:9000'}
className="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white disabled:opacity-50"
            />
            <button
              type="button"
              onClick={handleAddPort}
              disabled={formData.protocol === 'icmp' || formData.protocol === 'igmp'}
className="px-4 py-2 text-sm font-bold uppercase text-white bg-purple-active hover:bg-purple-600 rounded-none disabled:opacity-50 border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all"
            >
              Add
            </button>
          </div>

          {/* Destination port input error */}
          {portInputError && (
            <p className="text-xs text-red-500 mt-1">{portInputError}</p>
          )}

            {/* Destination port format hint */}
            {formData.protocol !== 'icmp' && formData.protocol !== 'igmp' && (
            <div className="mt-2">
              <p className="text-xs text-gray-500">
                Single: <code className="bg-gray-200 text-gray-800 dark:bg-gray-800 dark:text-gray-200 px-1 rounded">22</code>, Multiple: <code className="bg-gray-200 text-gray-800 dark:bg-gray-800 dark:text-gray-200 px-1 rounded">80,443</code>, Range: <code className="bg-gray-200 text-gray-800 dark:bg-gray-800 dark:text-gray-200 px-1 rounded">8000:9000</code>
              </p>
            </div>
          )}
</div>
{/* Collapsible Source Ports Section */}
<div className="border border-gray-200 dark:border-gray-border rounded-none overflow-hidden">
            <button
              type="button"
              onClick={() => setShowSourcePorts(!showSourcePorts)}
className="w-full px-4 py-3 flex items-center justify-between bg-gray-50 dark:bg-charcoal-darkest hover:bg-gray-100 dark:hover:bg-charcoal-dark transition-colors"
>
<span className="text-sm font-medium text-gray-700 dark:text-amber-primary">Source Ports (Optional)</span>
<svg className={`w-4 h-4 text-gray-500 transition-transform duration-150 ${showSourcePorts ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
</svg>
</button>
<div className={`transition-all duration-150 ease-in-out ${showSourcePorts ? 'max-h-96 opacity-100' : 'max-h-0 opacity-0'} overflow-hidden`}>
<div className="p-4 space-y-2">
<p className="text-xs text-gray-500 dark:text-amber-muted">Optional. Match traffic from specific source ports.</p>
{sourcePortChips.length > 0 && (
<div className="flex flex-wrap gap-2 mb-2">
{sourcePortChips.map((port, idx) => (
<span key={idx} className="px-2 py-1 bg-gray-100 dark:bg-charcoal-darkest rounded-none text-sm flex items-center gap-1 text-gray-900 dark:text-white">
{port}
<X className="w-3 h-3 text-gray-500 hover:text-red-500 cursor-pointer" onClick={() => handleRemoveSourcePort(port)} />
</span>
))}
</div>
)}
<div className="flex gap-2">
<input type="text" value={sourcePortInput} onChange={e => { setSourcePortInput(e.target.value); setSourcePortInputError('') }}
onKeyDown={handleSourcePortInputKeyDown} disabled={formData.protocol === 'icmp' || formData.protocol === 'igmp'}
placeholder={formData.protocol === 'icmp' ? 'N/A for ICMP' : formData.protocol === 'igmp' ? 'N/A for IGMP' : '67 or 53,5353'}
className="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white disabled:opacity-50" />
<button type="button" onClick={handleAddSourcePort} disabled={formData.protocol === 'icmp' || formData.protocol === 'igmp'}
className="px-4 py-2 text-sm font-medium text-white bg-purple-active hover:bg-purple-active/80 rounded-none disabled:opacity-50">Add</button>
</div>
{sourcePortInputError && <p className="text-xs text-red-500 mt-1">{sourcePortInputError}</p>}
{formData.protocol !== 'icmp' && formData.protocol !== 'igmp' && (
<div className="mt-2">
<p className="text-xs text-gray-500">
Single: <code className="bg-gray-200 text-gray-800 dark:bg-gray-800 dark:text-gray-200 px-1 rounded">67</code>, Multiple: <code className="bg-gray-200 text-gray-800 dark:bg-gray-800 dark:text-gray-200 px-1 rounded">53,5353</code>, Range: <code className="bg-gray-200 text-gray-800 dark:bg-gray-800 dark:text-gray-200 px-1 rounded">60000:65535</code>
</p>
</div>
)}
</div>
</div>
</div>
{/* Collapsible Description Section */}
<div className="border border-gray-200 dark:border-gray-border rounded-none overflow-hidden">
            <button type="button" onClick={() => setShowDescription(!showDescription)}
className="w-full px-4 py-3 flex items-center justify-between bg-gray-50 dark:bg-charcoal-darkest hover:bg-gray-100 dark:hover:bg-charcoal-dark transition-colors">
<span className="text-sm font-medium text-gray-700 dark:text-amber-primary">Description (Optional)</span>
<svg className={`w-4 h-4 text-gray-500 transition-transform duration-150 ${showDescription ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
</svg>
</button>
<div className={`transition-all duration-150 ease-in-out ${showDescription ? 'max-h-32 opacity-100' : 'max-h-0 opacity-0'} overflow-hidden`}>
<div className="p-4">
<textarea value={formData.description} onChange={e => setFormData(d => ({ ...d, description: e.target.value }))}
            rows={2} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white"
placeholder="Add a description for this service..." />
</div>
</div>
</div>
<InlineError message={formErrors._general} />
</form>
{/* Fixed Footer */}
<div className="px-6 py-4 border-t border-gray-200 dark:border-gray-border flex justify-end gap-3 shrink-0 bg-white dark:bg-charcoal-dark rounded-none">
<button type="button" onClick={closeModal} className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-none hover:bg-gray-50 dark:hover:bg-charcoal-darkest">Cancel</button>
<button type="submit" form="service-form" className="px-4 py-2 text-sm font-bold uppercase text-white bg-purple-active hover:bg-purple-600 rounded-none border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all">{editService ? 'Save Changes' : 'Create Service'}</button>
</div>
</div>
</div>
)}

      {deleteTarget && (
        <ConfirmModal
          title="Delete Service"
          message={`Delete service "${deleteTarget.name}"? Policies using this service will be affected.`}
          onConfirm={handleDeleteConfirm}
          onCancel={() => setDeleteTarget(null)}
          danger
        />
      )}

      {/* Conflict Error Modal */}
      {conflictError && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none w-full max-w-lg mx-4 p-6">
            <div className="flex items-start gap-3">
              <div className="flex-shrink-0 w-10 h-10 rounded-none bg-red-100 dark:bg-red-900/30 flex items-center justify-center">
                <svg className="w-6 h-6 text-red-600 dark:text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral mb-2">
                  Cannot Delete Service
                </h3>
                <p className="text-sm text-gray-600 dark:text-amber-muted mb-3">
                  The service <span className="font-medium text-gray-900 dark:text-white">&quot;{conflictError.serviceName}&quot;</span> cannot be deleted because it is used by the following policies:
                </p>
                <ul className="mb-4 space-y-1">
                  {conflictError.policies.map((policy, idx) => (
                    <li key={idx} className="text-sm text-gray-700 dark:text-amber-primary flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-none bg-purple-active"></span>
                      {policy}
                    </li>
                  ))}
                </ul>
                <p className="text-sm text-gray-500 dark:text-amber-muted">
                  Remove this service from the policies above before deleting it.
                </p>
              </div>
            </div>
            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setConflictError(null)}
                className="px-4 py-2 text-sm font-bold uppercase text-white bg-purple-active hover:bg-purple-600 rounded-none border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all"
              >
                Got it
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
