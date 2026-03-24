import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Lock } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useCrudModal } from '../hooks/useCrudModal'
import { useToastContext } from '../hooks/ToastContext'
import ConfirmModal from '../components/ConfirmModal'
import SearchableSelect from '../components/SearchableSelect'
import InlineError from '../components/InlineError'
import EmptyState from '../components/EmptyState'
import DataTable from '../components/DataTable'
import TableSkeleton from '../components/TableSkeleton'

export default function Groups() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const { modalOpen, editItem: editGroup, setEditItem: setEditGroup, form: formData, setForm: setFormData, setFormForEdit, handleOpenAdd, handleCancel, setModalOpen } = useCrudModal({ name: '', description: '' })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [newMember, setNewMember] = useState({ type: 'ip', value: '', label: '' })
  const [memberType, setMemberType] = useState('ip')
  const [formErrors, setFormErrors] = useState({})
  const openAdd = () => { setFormErrors({}); handleOpenAdd() }
  const openEdit = (g) => {
    setEditGroup(g); setFormForEdit(g); setFormErrors({}); setModalOpen(true)
  }
  const closeModal = () => { handleCancel() }

  const { data: groups, isLoading } = useQuery({
    queryKey: QUERY_KEYS.groups,
    queryFn: () => api.get('/groups'),
  })

  const { data: membersData } = useQuery({
    queryKey: QUERY_KEYS.members(editGroup?.id),
    queryFn: () => api.get(`/groups/${editGroup.id}/members`),
    enabled: !!editGroup?.id,
  })
  const members = membersData || []

  const groupOptions = (groups || []).filter(g => g.name !== 'any' && g.name !== 'localhost').map(g => ({ value: g.id, label: g.name }))

  const createMutation = useMutation({
    mutationFn: (data) => api.post('/groups', data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.groups }); closeModal() },
    onError: (err) => setFormErrors({ _general: err.message }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }) => api.put(`/groups/${id}`, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.groups }); closeModal() },
    onError: (err) => setFormErrors({ _general: err.message }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => api.delete(`/groups/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.groups }); setDeleteTarget(null) },
    onError: (err) => showToast(err.message, 'error'),
  })

  const addMemberMutation = useMutation({
    mutationFn: ({ groupId, member }) => api.post(`/groups/${groupId}/members`, member),
    onSuccess: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.members(editGroup.id) }) },
    onError: (err) => setFormErrors({ _general: err.message }),
  })

  const deleteMemberMutation = useMutation({
    mutationFn: ({ groupId, memberId }) => api.delete(`/groups/${groupId}/members/${memberId}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.members(editGroup.id) }) },
    onError: (err) => showToast(err.message, 'error'),
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    if (editGroup) updateMutation.mutate({ id: editGroup.id, data: formData })
    else createMutation.mutate(formData)
  }

  const handleAddMember = () => {
    if (!newMember.value) return
    if (memberType === 'group' && newMember.value === editGroup?.id) {
      setFormErrors({ _general: 'Cannot add group as member of itself' })
      return
    }
    addMemberMutation.mutate({ groupId: editGroup.id, member: { type: memberType, value: newMember.value, label: newMember.label } })
    setNewMember({ type: memberType, value: '', label: '' })
  }

  if (isLoading) return <TableSkeleton rows={3} columns={4} />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Groups</h1>
        <button onClick={openAdd} className="flex items-center gap-2 px-4 py-2 bg-runic-600 hover:bg-runic-700 text-white text-sm font-medium rounded-lg">
          <Plus className="w-4 h-4" /> New Group
        </button>
      </div>

      {!groups?.length ? (
        <EmptyState title="No groups yet" message="Create groups to organize IPs, CIDRs, and nested groups." action="New Group" onAction={openAdd} />
      ) : (
        <DataTable columns={[
          { key: 'name', label: 'Name', render: (g) => (
            <div className="flex items-center gap-2">
              {['any', 'localhost'].includes(g.name) && <Lock className="w-4 h-4 text-gray-400" />}
              <span className="font-medium text-gray-900 dark:text-white">{g.name}</span>
            </div>
          )},
          { key: 'description', label: 'Description', render: (g) => g.description || '—' },
          { key: 'member_count', label: 'Members', render: (g) => g.member_count || 0 },
          { key: 'actions', label: 'Actions', render: (g) => (
            <div className="flex items-center gap-2">
              <button onClick={(e) => { e.stopPropagation(); openEdit(g) }} className="px-3 py-1 text-xs font-medium text-runic-600 hover:bg-runic-50 dark:hover:bg-runic-900 rounded">Edit</button>
              {!['any', 'localhost'].includes(g.name) && (
                <button onClick={(e) => { e.stopPropagation(); setDeleteTarget(g) }} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"><Trash2 className="w-4 h-4 text-red-500" /></button>
              )}
            </div>
          )},
        ]} data={groups} />
      )}

      {/* Add/Edit Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-xl w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{editGroup ? 'Edit Group' : 'New Group'}</h3>
            </div>
            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
                <input type="text" value={formData.name} onChange={e => setFormData(d => ({ ...d, name: e.target.value }))} required disabled={editGroup && ['any', 'localhost'].includes(editGroup.name)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white disabled:opacity-50" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Description</label>
                <textarea value={formData.description} onChange={e => setFormData(d => ({ ...d, description: e.target.value }))} rows={2} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" />
              </div>

              {editGroup && !['any', 'localhost'].includes(editGroup.name) && (
                <>
                  <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
                    <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">Members</h4>
                    {members.length > 0 && (
                      <table className="w-full text-sm mb-3">
                        <thead className="bg-gray-50 dark:bg-gray-900">
                          <tr>
                            <th className="text-left px-3 py-2 font-medium text-gray-500">Type</th>
                            <th className="text-left px-3 py-2 font-medium text-gray-500">Value</th>
                            <th className="text-left px-3 py-2 font-medium text-gray-500">Label</th>
                            <th className="text-left px-3 py-2 font-medium text-gray-500"></th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                          {members.map(m => (
                            <tr key={m.id}>
                              <td className="px-3 py-2 text-gray-500">{m.type}</td>
                              <td className="px-3 py-2 text-gray-900 dark:text-white">{m.value}</td>
                              <td className="px-3 py-2 text-gray-500">{m.label || '—'}</td>
                              <td className="px-3 py-2"><button type="button" onClick={() => deleteMemberMutation.mutate({ groupId: editGroup.id, memberId: m.id })} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"><Trash2 className="w-4 h-4 text-red-500" /></button></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                    <div className="flex gap-2 items-end">
                      <div className="w-24">
                        <label className="block text-xs text-gray-500 mb-1">Type</label>
                        <select value={memberType} onChange={e => setMemberType(e.target.value)} className="w-full px-2 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white">
                          <option value="ip">IP</option>
                          <option value="cidr">CIDR</option>
                          <option value="group">Group</option>
                        </select>
                      </div>
                      <div className="flex-1">
                        <label className="block text-xs text-gray-500 mb-1">Value</label>
                        <input type="text" value={memberType === 'group' ? '' : newMember.value} onChange={e => setNewMember(d => ({ ...d, value: e.target.value }))} placeholder={memberType === 'cidr' ? '10.0.0.0/8' : '10.0.1.50'} className="w-full px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white" />
                        {memberType === 'group' && (
                          <SearchableSelect options={groupOptions.filter(o => o.value !== editGroup?.id)} value={newMember.value} onChange={v => setNewMember(d => ({ ...d, value: v }))} placeholder="Select group" />
                        )}
                      </div>
                      <div className="w-32">
                        <label className="block text-xs text-gray-500 mb-1">Label</label>
                        <input type="text" value={newMember.label} onChange={e => setNewMember(d => ({ ...d, label: e.target.value }))} placeholder="Optional" className="w-full px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white" />
                      </div>
                      <button type="button" onClick={handleAddMember} className="px-3 py-1.5 text-sm bg-runic-600 hover:bg-runic-700 text-white rounded-lg">Add</button>
                    </div>
                  </div>
                </>
              )}

              <InlineError message={formErrors._general} />
              <div className="flex justify-end gap-3 pt-2">
                <button type="button" onClick={closeModal} className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg">Cancel</button>
                <button type="submit" className="px-4 py-2 text-sm font-medium text-white bg-runic-600 hover:bg-runic-700 rounded-lg">{editGroup ? 'Save Changes' : 'Create Group'}</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {deleteTarget && (
        <ConfirmModal
          title="Delete Group"
          message={`Delete group "${deleteTarget.name}"?`}
          onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
          onCancel={() => setDeleteTarget(null)}
          danger
        />
      )}
    </div>
  )
}
