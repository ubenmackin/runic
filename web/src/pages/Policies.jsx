import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Pencil, Trash2, Eye } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useCrudModal } from '../hooks/useCrudModal'
import { useToastContext } from '../hooks/ToastContext'
import ConfirmModal from '../components/ConfirmModal'
import SearchableSelect from '../components/SearchableSelect'
import ToggleSwitch from '../components/ToggleSwitch'
import InlineError from '../components/InlineError'
import EmptyState from '../components/EmptyState'
import DataTable from '../components/DataTable'
import TableSkeleton from '../components/TableSkeleton'

export default function Policies() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const { modalOpen, setModalOpen, editItem: editPolicy, setEditItem: setEditPolicy, form: formData, setForm: setFormData, setFormForEdit, handleOpenAdd, handleCancel } = useCrudModal({ name: '', description: '', source_group_id: '', service_id: '', target_server_id: '', action: 'accept', priority: 100, enabled: true })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [filterServer, setFilterServer] = useState(null)
  const [showDisabled, setShowDisabled] = useState(false)
  const [preview, setPreview] = useState(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [formErrors, setFormErrors] = useState({})
  const openAdd = () => { setFormErrors({}); setPreview(null); handleOpenAdd() }
  const openEdit = (p) => { setEditPolicy(p); setFormForEdit(p); setFormErrors({}); setPreview(null); setModalOpen(true) }
  const closeModal = () => { handleCancel(); setPreview(null) }

  const { data: policies, isLoading } = useQuery({
    queryKey: QUERY_KEYS.policies(),
    queryFn: () => api.get('/policies'),
  })

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

  const serverOptions = (peers || []).map(s => ({ value: s.id, label: s.hostname }))
  const groupOptions = (groups || []).map(g => ({ value: g.id, label: g.name }))
  const serviceOptions = (services || []).map(s => ({ value: s.id, label: s.name }))

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
    if (!formData.source_group_id || !formData.service_id || !formData.target_server_id) {
      setFormErrors({ _general: 'Select source group, service, and target server to preview' })
      return
    }
    setPreviewLoading(true)
    try {
      const data = await api.post('/policies/preview', { source_group_id: formData.source_group_id, service_id: formData.service_id, target_server_id: formData.target_server_id })
      setPreview(data)
      setFormErrors({})
    } catch (err) {
      setFormErrors({ _general: err.message })
    } finally {
      setPreviewLoading(false)
    }
  }

  const filteredPolicies = (policies || []).filter(p => {
    if (!showDisabled && !p.enabled) return false
    if (filterServer && p.target_server_id !== filterServer) return false
    return true
  }).sort((a, b) => a.priority - b.priority)

  const getServerHostname = (id) => peers?.find(s => s.id === id)?.hostname || id
  const getGroupName = (id) => groups?.find(g => g.id === id)?.name || id
  const getServiceName = (id) => services?.find(s => s.id === id)?.name || id

  if (isLoading) return <TableSkeleton rows={3} columns={7} />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Policies</h1>
        <button onClick={openAdd} className="flex items-center gap-2 px-4 py-2 bg-runic-600 hover:bg-runic-700 text-white text-sm font-medium rounded-lg">
          <Plus className="w-4 h-4" /> New Policy
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-4 items-center bg-white dark:bg-gray-800 p-4 rounded-xl">
        <div className="w-48">
          <SearchableSelect options={[{ value: '', label: 'All Servers' }, ...serverOptions]} value={filterServer || ''} onChange={v => setFilterServer(v || null)} placeholder="Filter by server" />
        </div>
        <label className="flex items-center gap-2 cursor-pointer">
          <ToggleSwitch checked={showDisabled} onChange={setShowDisabled} />
          <span className="text-sm text-gray-700 dark:text-gray-300">Show disabled</span>
        </label>
      </div>

      {!filteredPolicies.length ? (
        <EmptyState title="No policies yet" message="Create policies to define firewall rules for your servers." action="New Policy" onAction={openAdd} />
      ) : (
        <DataTable columns={[
          { key: 'enabled', label: 'Enabled', render: (p) => <ToggleSwitch checked={p.enabled} onChange={(v) => toggleMutation.mutate({ id: p.id, enabled: v })} /> },
          { key: 'name', label: 'Name', render: (p) => <span className="font-medium text-gray-900 dark:text-white">{p.name}</span> },
          { key: 'source_group_id', label: 'Source', render: (p) => getGroupName(p.source_group_id) },
          { key: 'service_id', label: 'Service', render: (p) => getServiceName(p.service_id) },
          { key: 'target_server_id', label: 'Target', render: (p) => getServerHostname(p.target_server_id) },
          { key: 'action', label: 'Action', render: (p) => (
            <span className={`px-2 py-0.5 rounded text-xs font-medium ${p.action === 'accept' ? 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300'}`}>
              {p.action.toUpperCase()}
            </span>
          )},
          { key: 'priority', label: 'Priority' },
          { key: 'actions', label: 'Actions', render: (p) => (
            <div className="flex items-center gap-2">
              <button onClick={(e) => { e.stopPropagation(); openEdit(p) }} className="p-1.5 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"><Pencil className="w-4 h-4 text-gray-500" /></button>
              <button onClick={(e) => { e.stopPropagation(); setDeleteTarget(p) }} className="p-1.5 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"><Trash2 className="w-4 h-4 text-red-500" /></button>
            </div>
          )},
        ]} data={filteredPolicies} />
      )}

      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-xl w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{editPolicy ? 'Edit Policy' : 'New Policy'}</h3>
            </div>
            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
                  <input type="text" value={formData.name} onChange={e => setFormData(d => ({ ...d, name: e.target.value }))} required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Priority</label>
                  <input type="number" value={formData.priority} onChange={e => setFormData(d => ({ ...d, priority: parseInt(e.target.value) || 100 }))} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Description</label>
                <textarea value={formData.description} onChange={e => setFormData(d => ({ ...d, description: e.target.value }))} rows={2} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" />
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Source Group</label>
                  <SearchableSelect options={groupOptions} value={formData.source_group_id} onChange={v => setFormData(d => ({ ...d, source_group_id: v }))} placeholder="Select group" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Service</label>
                  <SearchableSelect options={serviceOptions} value={formData.service_id} onChange={v => setFormData(d => ({ ...d, service_id: v }))} placeholder="Select service" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Target Server</label>
                  <SearchableSelect options={serverOptions} value={formData.target_server_id} onChange={v => setFormData(d => ({ ...d, target_server_id: v }))} placeholder="Select server" />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Action</label>
                <div className="flex gap-4">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input type="radio" name="action" value="accept" checked={formData.action === 'accept'} onChange={e => setFormData(d => ({ ...d, action: e.target.value }))} className="text-runic-600" />
                    <span className="text-sm text-green-700 dark:text-green-400 font-medium">ACCEPT</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input type="radio" name="action" value="log_drop" checked={formData.action === 'log_drop'} onChange={e => setFormData(d => ({ ...d, action: e.target.value }))} className="text-runic-600" />
                    <span className="text-sm text-red-700 dark:text-red-400 font-medium">LOG+DROP</span>
                  </label>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <input type="checkbox" id="enabled" checked={formData.enabled} onChange={e => setFormData(d => ({ ...d, enabled: e.target.checked }))} className="w-4 h-4 rounded border-gray-300" />
                <label htmlFor="enabled" className="text-sm text-gray-700 dark:text-gray-300">Enabled</label>
              </div>

              {/* Preview */}
              <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
                <button type="button" onClick={fetchPreview} disabled={previewLoading} className="flex items-center gap-2 text-sm text-runic-600 hover:text-runic-700 mb-2">
                  <Eye className="w-4 h-4" /> {previewLoading ? 'Loading...' : 'Preview Rules'}
                </button>
                {preview && (
                  <div className="p-3 bg-gray-900 dark:bg-black rounded-lg text-xs font-mono">
                    {preview.rules?.map((rule, i) => (
                      <p key={i} className="text-green-400">{rule}</p>
                    ))}
                  </div>
                )}
              </div>

              <InlineError message={formErrors._general} />
              <div className="flex justify-end gap-3 pt-2">
                <button type="button" onClick={closeModal} className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg">Cancel</button>
                <button type="submit" className="px-4 py-2 text-sm font-medium text-white bg-runic-600 hover:bg-runic-700 rounded-lg">{editPolicy ? 'Save Changes' : 'Create Policy'}</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {deleteTarget && (
        <ConfirmModal
          title="Delete Policy"
          message={`Delete policy "${deleteTarget.name}"? Rules will be removed from ${getServerHostname(deleteTarget.target_server_id)} on next push.`}
          onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
          onCancel={() => setDeleteTarget(null)}
          danger
        />
      )}
    </div>
  )
}
