import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Pencil, Trash2 } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useCrudModal } from '../hooks/useCrudModal'
import { useToastContext } from '../hooks/ToastContext'
import ConfirmModal from '../components/ConfirmModal'
import InlineError from '../components/InlineError'
import EmptyState from '../components/EmptyState'
import DataTable from '../components/DataTable'

const PROTOCOLS = ['tcp', 'udp', 'both', 'icmp']

export default function Services() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const { modalOpen, setModalOpen, editItem: editService, setEditItem: setEditService, form: formData, setForm: setFormData, setFormForEdit, handleOpenAdd, handleCancel: closeModal } = useCrudModal({ name: '', protocol: 'tcp', ports: '', description: '' })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [formErrors, setFormErrors] = useState({})
  const openAdd = () => { setFormErrors({}); handleOpenAdd() }
  const openEdit = (s) => { setEditService(s); setFormForEdit(s); setFormErrors({}); setModalOpen(true) }

  const { data: services, isLoading } = useQuery({
    queryKey: QUERY_KEYS.services,
    queryFn: () => api.get('/services'),
  })

  const createMutation = useMutation({
    mutationFn: (data) => api.post('/services', data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.services }); closeModal() },
    onError: (err) => setFormErrors({ _general: err.message }),
  })

  const updateMutation = useMutation({
    mutationFn: (data) => api.put(`/services/${editService.id}`, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.services }); closeModal() },
    onError: (err) => setFormErrors({ _general: err.message }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => api.delete(`/services/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.services }); setDeleteTarget(null) },
    onError: (err) => showToast(err.message, 'error'),
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

  if (isLoading) return <div className="animate-pulse text-gray-500">Loading services...</div>

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Services</h1>
        <button onClick={openAdd} className="flex items-center gap-2 px-4 py-2 bg-runic-600 hover:bg-runic-700 text-white text-sm font-medium rounded-lg">
          <Plus className="w-4 h-4" /> New Service
        </button>
      </div>

      {!services?.length ? (
        <EmptyState title="No services yet" message="Create services to define port bundles for your policies." action="New Service" onAction={openAdd} />
      ) : (
        <DataTable columns={[
          { key: 'name', label: 'Name', render: (s) => <span className="font-medium text-gray-900 dark:text-white">{s.name}</span> },
          { key: 'protocol', label: 'Protocol', render: (s) => protocolLabel(s.protocol) },
          { key: 'ports', label: 'Ports', render: (s) => <span className="font-mono text-xs">{s.ports || '—'}</span> },
          { key: 'description', label: 'Description', render: (s) => s.description || '—' },
          { key: 'actions', label: 'Actions', render: (s) => (
            <div className="flex items-center gap-2">
              <button onClick={(e) => { e.stopPropagation(); openEdit(s) }} className="p-1.5 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"><Pencil className="w-4 h-4 text-gray-500" /></button>
              <button onClick={(e) => { e.stopPropagation(); setDeleteTarget(s) }} className="p-1.5 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"><Trash2 className="w-4 h-4 text-red-500" /></button>
            </div>
          )},
        ]} data={services} />
      )}

      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-xl w-full max-w-md mx-4">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{editService ? 'Edit Service' : 'New Service'}</h3>
            </div>
            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
                <input type="text" value={formData.name} onChange={e => setFormData(d => ({ ...d, name: e.target.value }))} required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Protocol</label>
                <div className="flex gap-4">
                  {PROTOCOLS.map(p => (
                    <label key={p} className="flex items-center gap-2 cursor-pointer">
                      <input type="radio" name="protocol" value={p} checked={formData.protocol === p} onChange={e => setFormData(d => ({ ...d, protocol: e.target.value }))} className="text-runic-600" />
                      <span className="text-sm text-gray-700 dark:text-gray-300">{protocolLabel(p)}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Ports</label>
                <input type="text" value={formData.ports} onChange={e => setFormData(d => ({ ...d, ports: e.target.value }))} disabled={formData.protocol === 'icmp'} placeholder={formData.protocol === 'icmp' ? 'N/A for ICMP' : '22 or 80,443 or 8000:9000'} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white disabled:opacity-50" />
                {portHint()}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Description</label>
                <textarea value={formData.description} onChange={e => setFormData(d => ({ ...d, description: e.target.value }))} rows={2} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" />
              </div>
              {formData.ports && formData.protocol !== 'icmp' && (
                <div className="p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                  <p className="text-xs text-gray-500 mb-1">Rule preview:</p>
                  <code className="text-sm text-runic-600">{previewRule()}</code>
                </div>
              )}
              <InlineError message={formErrors._general} />
              <div className="flex justify-end gap-3 pt-2">
                <button type="button" onClick={closeModal} className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg">Cancel</button>
                <button type="submit" className="px-4 py-2 text-sm font-medium text-white bg-runic-600 hover:bg-runic-700 rounded-lg">{editService ? 'Save Changes' : 'Create Service'}</button>
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
