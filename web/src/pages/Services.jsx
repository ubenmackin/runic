import { useState, useMemo, useCallback, useRef, useEffect } from 'react'
import { useTableSort } from '../hooks/useTableSort'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Pencil, Trash2, RefreshCw, ArrowUp, ArrowDown, ArrowUpDown, X, Search } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useCrudModal } from '../hooks/useCrudModal'
import { useToastContext } from '../hooks/ToastContext'
import ConfirmModal from '../components/ConfirmModal'
import InlineError from '../components/InlineError'
import EmptyState from '../components/EmptyState'
import TableSkeleton from '../components/TableSkeleton'
import SearchableSelect from '../components/SearchableSelect'

const PROTOCOLS = ['tcp', 'udp', 'both', 'icmp']
const PROTOCOL_OPTIONS = [
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
  { value: 'both', label: 'TCP+UDP' },
  { value: 'icmp', label: 'ICMP' }
]

// Protocol options for user-created services (excludes ICMP which is system-only)
const USER_PROTOCOL_OPTIONS = [
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
  { value: 'both', label: 'TCP+UDP' },
]

export default function Services() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const { modalOpen, setModalOpen, editItem: editService, setEditItem: setEditService, form: formData, setForm: setFormData, setFormForEdit, handleOpenAdd, handleCancel: closeModal } = useCrudModal({ name: '', protocol: 'tcp', ports: '', description: '' })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [formErrors, setFormErrors] = useState({})
  const [portChips, setPortChips] = useState([])
  const [portInput, setPortInput] = useState('')
  const [portInputError, setPortInputError] = useState('')

  // Sorting state (persisted per-user)
  const { sortConfig, handleSort } = useTableSort('services', { key: 'name', direction: 'asc' })

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

  const openAdd = () => { setFormErrors({}); setPortChips([]); setPortInput(''); setPortInputError(''); handleOpenAdd() }
  const openEdit = (s) => {
    setEditService(s);
    setFormForEdit(s);
    setFormErrors({});
    // Initialize port chips from existing ports
    const ports = s.ports ? s.ports.split(',').map(p => p.trim()).filter(Boolean) : []
    setPortChips(ports)
    setPortInput('')
    setPortInputError('')
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

  // Filtered and sorted data
  const processedServices = useMemo(() => {
    if (!services) return []

    // Filter by search term
    let filtered = services
    if (searchTerm) {
      const term = searchTerm.toLowerCase()
      filtered = services.filter(s => {
        const name = (s.name || '').toLowerCase()
        const protocol = (s.protocol || '').toLowerCase()
        const ports = (s.ports || '').toLowerCase()
        const description = (s.description || '').toLowerCase()
        return name.includes(term) || protocol.includes(term) || ports.includes(term) || description.includes(term)
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
        case 'protocol':
          aVal = (a.protocol || '').toLowerCase()
          bVal = (b.protocol || '').toLowerCase()
          break
        case 'ports':
          // Numeric sort - extract first port number
          aVal = parseInt((a.ports || '0').split(',')[0].split(':')[0]) || 0
          bVal = parseInt((b.ports || '0').split(',')[0].split(':')[0]) || 0
          break
        case 'description':
          aVal = (a.description || '').toLowerCase()
          bVal = (b.description || '').toLowerCase()
          break
        default:
          return 0
      }
      if (aVal < bVal) return sortConfig.direction === 'asc' ? -1 : 1
      if (aVal > bVal) return sortConfig.direction === 'asc' ? 1 : -1
      return 0
    })
    return sorted
  }, [services, searchTerm, sortConfig])

  const createMutation = useMutation({
    mutationFn: (data) => api.post('/services', data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.services() }); closeModal() },
    onError: (err) => setFormErrors({ _general: err.message }),
  })

  const updateMutation = useMutation({
    mutationFn: (data) => api.put(`/services/${editService.id}`, data),
    onMutate: async (newData) => {
      await qc.cancelQueries({ queryKey: QUERY_KEYS.services() })
      const previousServices = qc.getQueryData(QUERY_KEYS.services())
      qc.setQueryData(QUERY_KEYS.services(), old => old?.map(s => s.id === editService.id ? { ...s, ...newData } : s) || [])
      return { previousServices }
    },
    onError: (err, newData, context) => {
      qc.setQueryData(QUERY_KEYS.services(), context.previousServices)
      setFormErrors({ _general: err.message })
    },
    onSettled: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.services() }); closeModal() },
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => api.delete(`/services/${id}`),
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey: QUERY_KEYS.services() })
      const previousServices = qc.getQueryData(QUERY_KEYS.services())
      qc.setQueryData(QUERY_KEYS.services(), old => old?.filter(s => s.id !== id) || [])
      return { previousServices }
    },
    onError: (err, id, context) => {
      qc.setQueryData(QUERY_KEYS.services(), context.previousServices)
      showToast(err.message, 'error')
    },
    onSettled: () => { setDeleteTarget(null) },
  })

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

  const handleSubmit = (e) => {
    e.preventDefault()
    // Join port chips into comma-separated string for API
    const portsValue = portChips.join(',')
    const submitData = { ...formData, ports: portsValue }
    if (editService) updateMutation.mutate(submitData)
    else createMutation.mutate(submitData)
  }

  const protocolLabel = (p) => ({ tcp: 'TCP', udp: 'UDP', both: 'TCP+UDP', icmp: 'ICMP' }[p] || p)
  const previewRule = () => {
    const portsValue = portChips.join(',')
    if (formData.protocol === 'icmp') return `icmp`
    if (!portsValue) return `${formData.protocol} dport ?`

    // Determine if multiport is needed
    const needsMultiport = portsValue.includes(',') || portsValue.includes(':')
    const portMatch = needsMultiport ? `-m multiport --dports ${portsValue}` : `--dport ${portsValue}`

    if (formData.protocol === 'both') {
      return `tcp ${portMatch}\nudp ${portMatch}`
    }
    return `${formData.protocol} ${portMatch}`
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

  if (isLoading) return <TableSkeleton rows={3} columns={5} />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-light-neutral">Services</h1>
          <p className="text-gray-600 dark:text-amber-muted">Define port and protocol bundles to simplify policy creation</p>
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
            <Plus className="w-4 h-4" /> New Service
          </button>
        </div>
      </div>

      {/* Search Bar */}
      <div className="relative flex-1 max-w-md">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
        <input
          type="text"
          placeholder="Search services by name, protocol, ports, or description..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full pl-9 pr-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral placeholder-gray-400 focus:ring-2 focus:ring-purple-active focus:border-purple-active"
        />
        {searchTerm && (
          <button
            onClick={() => setSearchTerm('')}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-light-neutral"
          >
            ×
          </button>
        )}
      </div>

      {!processedServices?.length ? (
        searchTerm ? (
          <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm p-8 text-center">
            <p className="text-gray-500 dark:text-amber-muted">No services match your search.</p>
          </div>
        ) : (
          <EmptyState title="No services yet" message="Create services to define port bundles for your policies." action="New Service" onAction={openAdd} />
        )
      ) : (
        <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 dark:bg-charcoal-darkest">
                <tr>
                  <th
                    className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted cursor-pointer hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none"
                    onClick={() => handleSort('name')}
                  >
                    Name <SortIndicator columnKey="name" />
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted cursor-pointer hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none"
                    onClick={() => handleSort('protocol')}
                  >
                    Protocol <SortIndicator columnKey="protocol" />
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted cursor-pointer hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none"
                    onClick={() => handleSort('ports')}
                  >
                    Ports <SortIndicator columnKey="ports" />
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted cursor-pointer hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none"
                    onClick={() => handleSort('description')}
                  >
                    Description <SortIndicator columnKey="description" />
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-border">
                {processedServices.map((service) => (
                  <tr key={service.id} className="">
                    <td className="px-4 py-3">
                      <span className="font-medium text-gray-900 dark:text-light-neutral">{service.name}</span>
                    </td>
                    <td className="px-4 py-3 text-gray-600 dark:text-amber-primary">
                      {protocolLabel(service.protocol)}
                    </td>
                    <td className="px-4 py-3">
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
                                  <span
                                    key={idx}
                                    className="px-2 py-0.5 text-xs font-medium rounded-full bg-purple-active/20 dark:bg-purple-active text-white whitespace-nowrap"
                                  >
                                    {port}
                                  </span>
                                ))}
                                {remainingCount > 0 && (
                                  <span
                                    className="px-2 py-0.5 text-xs font-medium rounded-full bg-gray-100 dark:bg-charcoal-darkest text-gray-600 dark:text-amber-muted whitespace-nowrap"
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
                    <td className="px-4 py-3 text-gray-600 dark:text-amber-primary">
                      {service.description || '—'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={(e) => { e.stopPropagation(); openEdit(service) }}
                          className={`p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded ${service.is_system ? 'text-gray-400 cursor-not-allowed opacity-50' : ''}`}
                          disabled={service.is_system}
                          title={service.is_system ? "System services cannot be edited" : "Edit"}
                        >
                          <Pencil className="w-4 h-4" />
                        </button>
                        {!service.is_system && (
                          <button
                            onClick={(e) => { e.stopPropagation(); setDeleteTarget(service) }}
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
        </div>
      )}

      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" tabIndex="-1" onKeyDown={(e) => { if (e.key === 'Escape') { closeModal() } }}>
          <div
            ref={modalRef}
            role="dialog"
            aria-modal="true"
            className="bg-white dark:bg-charcoal-dark rounded-xl shadow-xl w-full max-w-lg mx-4"
            tabIndex="-1"
          >
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border flex items-center justify-between">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">{editService ? 'Edit Service' : 'New Service'}</h3>
              <button onClick={closeModal} className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded">
                <X className="w-5 h-5 text-gray-500" />
              </button>
            </div>
            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Name</label>
                <input type="text" value={formData.name} onChange={e => setFormData(d => ({ ...d, name: e.target.value }))} required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white" />
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
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Ports</label>
                <p className="text-xs text-gray-500 dark:text-amber-muted mb-2">Allow network traffic and access only to specified ports. Select ports or port ranges between 1 and 65535.</p>

                {/* Port chips display */}
                {portChips.length > 0 && (
                  <div className="flex flex-wrap gap-2 mb-2">
                    {portChips.map((port, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-1 bg-gray-100 dark:bg-charcoal-darkest rounded-md text-sm flex items-center gap-1 text-gray-900 dark:text-white"
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

                {/* Port input */}
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={portInput}
                    onChange={e => { setPortInput(e.target.value); setPortInputError('') }}
                    onKeyDown={handlePortInputKeyDown}
                    disabled={formData.protocol === 'icmp'}
                    placeholder={formData.protocol === 'icmp' ? 'N/A for ICMP' : '22 or 80,443 or 8000:9000'}
                    className="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white disabled:opacity-50"
                  />
                  <button
                    type="button"
                    onClick={handleAddPort}
                    disabled={formData.protocol === 'icmp'}
                    className="px-4 py-2 text-sm font-medium text-white bg-purple-active hover:bg-purple-active/80 rounded-lg disabled:opacity-50"
                  >
                    Add
                  </button>
                </div>

                {/* Port input error */}
                {portInputError && (
                  <p className="text-xs text-red-500 mt-1">{portInputError}</p>
                )}

                {/* Port format hint */}
                {formData.protocol !== 'icmp' && (
                  <div className="mt-8 mb-2">
                    <p className="text-xs text-gray-500">
                      Single: <code className="bg-gray-200 text-gray-800 dark:bg-gray-800 dark:text-gray-200 px-1 rounded">22</code>, Multiple: <code className="bg-gray-200 text-gray-800 dark:bg-gray-800 dark:text-gray-200 px-1 rounded">80,443</code>, Range: <code className="bg-gray-200 text-gray-800 dark:bg-gray-800 dark:text-gray-200 px-1 rounded">8000:9000</code>
                    </p>
                  </div>
                )}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Description</label>
                <textarea value={formData.description} onChange={e => setFormData(d => ({ ...d, description: e.target.value }))} rows={2} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white" />
              </div>
              {portChips.length > 0 && formData.protocol !== 'icmp' && (
                <div className="p-3 bg-gray-50 dark:bg-charcoal-darkest rounded-lg">
                  <p className="text-xs text-gray-500 mb-1">Rule preview:</p>
                  <code className="text-sm text-runic-600 whitespace-pre-line">{previewRule()}</code>
                </div>
              )}
              <InlineError message={formErrors._general} />
              <div className="flex justify-end gap-3 pt-2">
                <button type="button" onClick={closeModal} className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-lg hover:bg-gray-50 dark:hover:bg-charcoal-darkest">Cancel</button>
                <button type="submit" className="px-4 py-2 text-sm font-medium text-white bg-purple-active hover:bg-purple-active/80 rounded-lg">{editService ? 'Save Changes' : 'Create Service'}</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {deleteTarget && (
        <ConfirmModal
          title="Delete Service"
          message={`Delete service "${deleteTarget.name}"? Policies using this service will be affected.`}
          onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
          onCancel={() => setDeleteTarget(null)}
          danger
        />
      )}
    </div>
  )
}
