import { useState, useMemo, useCallback } from 'react'
import { useTableSort } from '../hooks/useTableSort'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Pencil, Trash2, RefreshCw, ArrowUp, ArrowDown, ArrowUpDown, X } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useCrudModal } from '../hooks/useCrudModal'
import { useToastContext } from '../hooks/ToastContext'
import ConfirmModal from '../components/ConfirmModal'
import InlineError from '../components/InlineError'
import EmptyState from '../components/EmptyState'
import TableSkeleton from '../components/TableSkeleton'

const PROTOCOLS = ['tcp', 'udp', 'both', 'icmp']

export default function Services() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const { modalOpen, setModalOpen, editItem: editService, setEditItem: setEditService, form: formData, setForm: setFormData, setFormForEdit, handleOpenAdd, handleCancel: closeModal } = useCrudModal({ name: '', protocol: 'tcp', ports: '', description: '' })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [formErrors, setFormErrors] = useState({})

  // Sorting state (persisted per-user)
  const { sortConfig, handleSort } = useTableSort('services', { key: 'name', direction: 'asc' })

  // Search state
  const [searchTerm, setSearchTerm] = useState('')

  // Manual refresh state
  const [isManualRefreshing, setIsManualRefreshing] = useState(false)

  const openAdd = () => { setFormErrors({}); handleOpenAdd() }
  const openEdit = (s) => { setEditService(s); setFormForEdit(s); setFormErrors({}); setModalOpen(true) }

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

  const handleSubmit = (e) => {
    e.preventDefault()
    if (editService) updateMutation.mutate(formData)
    else createMutation.mutate(formData)
  }

  const portHint = () => {
    if (formData.protocol === 'icmp') return null
    return (
      <p className="text-xs text-gray-500 mt-1">
        Single: <code className="bg-gray-100 px-1 rounded">22</code>, Multiple: <code className="bg-gray-100 px-1 rounded">80,443</code>, Range: <code className="bg-gray-100 px-1 rounded">8000:9000</code>
      </p>
    )
  }

  const protocolLabel = (p) => ({ tcp: 'TCP', udp: 'UDP', both: 'TCP+UDP', icmp: 'ICMP' }[p] || p)
  const previewRule = () => {
    if (formData.protocol === 'icmp') return `icmp`
    if (!formData.ports) return `tcp dport ?`
    return `tcp dport ${formData.ports}`
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
        <h1 className="text-2xl font-bold text-gray-900 dark:text-light-neutral">Services</h1>
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
      <div className="relative max-w-md">
        <input
          type="text"
          placeholder="Search services by name, protocol, ports, or description..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full px-4 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral placeholder-gray-500 dark:placeholder-amber-muted focus:ring-2 focus:ring-purple-active focus:border-purple-active"
        />
        {searchTerm && (
          <button
            onClick={() => setSearchTerm('')}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-amber-primary"
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
                      <span className="font-mono text-xs">{service.ports || '—'}</span>
                    </td>
                    <td className="px-4 py-3 text-gray-600 dark:text-amber-primary">
                      {service.description || '—'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={(e) => { e.stopPropagation(); openEdit(service) }}
                          className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded"
                          title="Edit"
                        >
                          <Pencil className="w-4 h-4 text-gray-500" />
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); setDeleteTarget(service) }}
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
        </div>
      )}

      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-xl w-full max-w-md mx-4">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">{editService ? 'Edit Service' : 'New Service'}</h3>
            </div>
            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Name</label>
                <input type="text" value={formData.name} onChange={e => setFormData(d => ({ ...d, name: e.target.value }))} required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Protocol</label>
                <div className="flex gap-4">
                  {PROTOCOLS.map(p => (
                    <label key={p} className="flex items-center gap-2 cursor-pointer">
                      <input type="radio" name="protocol" value={p} checked={formData.protocol === p} onChange={e => setFormData(d => ({ ...d, protocol: e.target.value }))} className="text-runic-600" />
                      <span className="text-sm text-gray-700 dark:text-amber-primary">{protocolLabel(p)}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Ports</label>
                <input type="text" value={formData.ports} onChange={e => setFormData(d => ({ ...d, ports: e.target.value }))} disabled={formData.protocol === 'icmp'} placeholder={formData.protocol === 'icmp' ? 'N/A for ICMP' : '22 or 80,443 or 8000:9000'} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white disabled:opacity-50" />
                {portHint()}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Description</label>
                <textarea value={formData.description} onChange={e => setFormData(d => ({ ...d, description: e.target.value }))} rows={2} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white" />
              </div>
              {formData.ports && formData.protocol !== 'icmp' && (
                <div className="p-3 bg-gray-50 dark:bg-charcoal-darkest rounded-lg">
                  <p className="text-xs text-gray-500 mb-1">Rule preview:</p>
                  <code className="text-sm text-runic-600">{previewRule()}</code>
                </div>
              )}
              <InlineError message={formErrors._general} />
              <div className="flex justify-end gap-3 pt-2">
                <button type="button" onClick={closeModal} className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-darkest border border-gray-300 dark:border-gray-border rounded-lg">Cancel</button>
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
