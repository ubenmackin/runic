import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Pencil, Upload, Trash2, Server } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useCrudModal } from '../hooks/useCrudModal'
import { useToastContext } from '../hooks/ToastContext'
import StatusBadge from '../components/StatusBadge'
import ConfirmModal from '../components/ConfirmModal'
import SearchableSelect from '../components/SearchableSelect'
import InlineError from '../components/InlineError'
import EmptyState from '../components/EmptyState'
import DataTable from '../components/DataTable'
import TableSkeleton from '../components/TableSkeleton'

const OS_OPTIONS = [
  { value: 'ubuntu', label: 'Ubuntu' },
  { value: 'opensuse', label: 'openSUSE' },
  { value: 'raspbian', label: 'Raspbian' },
  { value: 'armbian', label: 'Armbian' },
]

const ARCH_OPTIONS = [
  { value: 'amd64', label: 'amd64' },
  { value: 'arm64', label: 'arm64' },
  { value: 'arm', label: 'arm' },
]

export default function Peers() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const { modalOpen, setModalOpen, editItem: editPeer, setEditItem: setEditPeer, form: formData, setForm: setFormData, setFormForEdit, handleOpenAdd, handleCancel: closeModal } = useCrudModal({ hostname: '', ip: '', os: 'ubuntu', arch: 'amd64', has_docker: false, description: '' })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [pushStatus, setPushStatus] = useState({})
  const [formErrors, setFormErrors] = useState({})
  const openAdd = () => { setFormErrors({}); handleOpenAdd() }
  const openEdit = (s) => { setEditPeer(s); setFormForEdit(s); setFormErrors({}); setModalOpen(true) }

  const { data: peers, isLoading } = useQuery({
    queryKey: QUERY_KEYS.peers,
    queryFn: () => api.get('/peers'),
    refetchInterval: 5000,
  })

  const createMutation = useMutation({
    mutationFn: (data) => api.post('/peers', data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.peers }); closeModal() },
    onError: (err) => setFormErrors({ _general: err.message }),
  })

  const updateMutation = useMutation({
    mutationFn: (data) => api.put(`/peers/${editPeer.id}`, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.peers }); closeModal() },
    onError: (err) => setFormErrors({ _general: err.message }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => api.delete(`/peers/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.peers }); setDeleteTarget(null) },
    onError: (err) => showToast(err.message, 'error'),
  })

  const pushMutation = useMutation({
    mutationFn: async (peer) => {
      setPushStatus(prev => ({ ...prev, [peer.id]: 'pushing' }))
      await api.post(`/peers/${peer.id}/push`)
    },
    onSuccess: (data, peer) => {
      setPushStatus(prev => ({ ...prev, [peer.id]: `Pushed v${data.bundle_version}` }))
      setTimeout(() => setPushStatus(prev => ({ ...prev, [peer.id]: null })), 5000)
      qc.invalidateQueries({ queryKey: QUERY_KEYS.peers })
    },
    onError: (err, peer) => {
      setPushStatus(prev => ({ ...prev, [peer.id]: `Error: ${err.message}` }))
      // Auto-clear error after 10 seconds
      setTimeout(() => setPushStatus(prev => ({ ...prev, [peer.id]: null })), 10000)
    },
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    if (editPeer) updateMutation.mutate(formData)
    else createMutation.mutate(formData)
  }

  if (isLoading) return <TableSkeleton rows={3} columns={7} />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Peers</h1>
        <button onClick={openAdd} className="flex items-center gap-2 px-4 py-2 bg-runic-600 hover:bg-runic-700 text-white text-sm font-medium rounded-lg">
          <Plus className="w-4 h-4" /> Add Peer
        </button>
      </div>

    {!peers?.length ? (
      <EmptyState icon={Server} title="No peers yet" message="Add your first peer to start managing firewall rules." action="Add Peer" onAction={openAdd} />
      ) : (
        <DataTable columns={[
          { key: 'hostname', label: 'Hostname', render: (s) => <span className="font-medium text-gray-900 dark:text-white">{s.hostname}</span> },
          { key: 'ip_address', label: 'IP' },
          { key: 'os', label: 'OS' },
          { key: 'arch', label: 'Arch' },
          { key: 'has_docker', label: 'Docker', render: (s) => s.has_docker ? '✓' : '—' },
          { key: 'status', label: 'Status', render: (s) => <StatusBadge status={s.status} /> },
          { key: 'bundle_version', label: 'Bundle', render: (s) => `v${s.bundle_version || 0}` },
          { key: 'actions', label: 'Actions', render: (s) => (
            <>
              <div className="flex items-center gap-2">
                <button onClick={(e) => { e.stopPropagation(); openEdit(s) }} className="p-1.5 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"><Pencil className="w-4 h-4 text-gray-500" /></button>
                <button onClick={(e) => { e.stopPropagation(); pushMutation.mutate(s) }} disabled={pushMutation.isPending} className="p-1.5 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"><Upload className="w-4 h-4 text-gray-500" /></button>
                <button onClick={(e) => { e.stopPropagation(); setDeleteTarget(s) }} className="p-1.5 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"><Trash2 className="w-4 h-4 text-red-500" /></button>
              </div>
              {pushStatus[s.id] && (
                <p className="text-xs text-runic-600 mt-1">{pushStatus[s.id]}</p>
              )}
            </>
          )},
        ]} data={peers} />
      )}

      {/* Add/Edit Modal */}
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
                <input type="text" value={formData.ip} onChange={e => setFormData(d => ({ ...d, ip: e.target.value }))} required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" />
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
    </div>
  )
}
