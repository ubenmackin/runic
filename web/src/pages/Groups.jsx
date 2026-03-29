import { useState, useRef, useEffect, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Lock, Users, Shield, Search, ArrowUp, ArrowDown, ArrowUpDown, X, RefreshCw, Pencil } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useCrudModal } from '../hooks/useCrudModal'
import { useTableSort } from '../hooks/useTableSort'
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
  const [formErrors, setFormErrors] = useState({})
  
  // Sorting state
  const { sortConfig, handleSort } = useTableSort('groups', { key: 'name', direction: 'asc' })
  
  // Search state
  const [searchQuery, setSearchQuery] = useState('')
  
  // Selected peer for adding to group
  const [selectedPeerId, setSelectedPeerId] = useState(null)
  const [isManualRefreshing, setIsManualRefreshing] = useState(false)

  // Modal ref for focus trap
  const modalRef = useRef(null)

  const openAdd = () => { setFormErrors({}); handleOpenAdd() }
  const openEdit = (g) => {
    setEditGroup(g)
    setFormForEdit(g)
    setFormErrors({})
    setSelectedPeerId(null)
    setModalOpen(true)
  }
  const closeModal = () => {
    handleCancel()
    setSelectedPeerId(null)
  }

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

  const { data: groups, isLoading, refetch } = useQuery({
    queryKey: QUERY_KEYS.groups(),
    queryFn: () => api.get('/groups'),
  })

  // Manual refresh handler
  const handleManualRefresh = useCallback(async () => {
    setIsManualRefreshing(true)
    await refetch()
    setIsManualRefreshing(false)
  }, [refetch])

  const { data: membersData, isLoading: membersLoading } = useQuery({
    queryKey: QUERY_KEYS.members(editGroup?.id),
    queryFn: () => api.get(`/groups/${editGroup.id}/members`),
    enabled: !!editGroup?.id,
  })
  const members = membersData || []

  // Fetch all peers for the "Add Peer" dropdown
  const { data: allPeers } = useQuery({
    queryKey: QUERY_KEYS.peers(),
    queryFn: () => api.get('/peers'),
    enabled: modalOpen && !!editGroup,
  })

  // Filter out peers already in the group for the dropdown
  const availablePeers = (allPeers || []).filter(
    peer => !members.some(m => m.id === peer.id)
  )
  const peerOptions = availablePeers.map(p => ({
    value: p.id,
    label: p.hostname || p.ip_address,
  }))

  // Sort groups based on sortConfig
  const sortedGroups = [...(groups || [])].sort((a, b) => {
    let aVal, bVal
    switch (sortConfig.key) {
      case 'name':
        aVal = a.name.toLowerCase()
        bVal = b.name.toLowerCase()
        break
      case 'peers':
        aVal = a.peer_count || 0
        bVal = b.peer_count || 0
        break
      case 'policies':
        aVal = a.policy_count || 0
        bVal = b.policy_count || 0
        break
      default:
        return 0
    }
    if (aVal < bVal) return sortConfig.direction === 'asc' ? -1 : 1
    if (aVal > bVal) return sortConfig.direction === 'asc' ? 1 : -1
    return 0
  })

  // Filter groups based on search query
  const filteredGroups = sortedGroups.filter(g => {
    if (!searchQuery) return true
    const query = searchQuery.toLowerCase()
    return (
      g.name.toLowerCase().includes(query) ||
      String(g.peer_count || 0).includes(query) ||
      String(g.policy_count || 0).includes(query)
    )
  })

  // Render sort indicator
  const SortIndicator = ({ columnKey }) => {
    if (sortConfig.key !== columnKey) {
      return <ArrowUpDown className="w-4 h-4 text-gray-400 ml-1" />
    }
    return sortConfig.direction === 'asc'
      ? <ArrowUp className="w-4 h-4 text-runic-500 ml-1" />
      : <ArrowDown className="w-4 h-4 text-runic-500 ml-1" />
  }

  const createMutation = useMutation({
    mutationFn: (data) => api.post('/groups', data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.groups() }); closeModal() },
    onError: (err) => setFormErrors({ _general: err.message }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }) => api.put(`/groups/${id}`, data),
    onMutate: async ({ id, data }) => {
      await qc.cancelQueries({ queryKey: QUERY_KEYS.groups() })
      const previousGroups = qc.getQueryData(QUERY_KEYS.groups())
      qc.setQueryData(QUERY_KEYS.groups(), old => old?.map(g => g.id === id ? { ...g, ...data } : g) || [])
      return { previousGroups }
    },
    onError: (err, vars, context) => {
      qc.setQueryData(QUERY_KEYS.groups(), context.previousGroups)
      setFormErrors({ _general: err.message })
    },
    onSettled: () => { qc.invalidateQueries({ queryKey: QUERY_KEYS.groups() }); closeModal() },
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => api.delete(`/groups/${id}`),
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey: QUERY_KEYS.groups() })
      const previousGroups = qc.getQueryData(QUERY_KEYS.groups())
      qc.setQueryData(QUERY_KEYS.groups(), old => old?.filter(g => g.id !== id) || [])
      return { previousGroups }
    },
    onError: (err, id, context) => {
      qc.setQueryData(QUERY_KEYS.groups(), context.previousGroups)
      showToast(err.message, 'error')
    },
    onSettled: () => { setDeleteTarget(null) },
  })

  const addMemberMutation = useMutation({
    mutationFn: ({ groupId, peerId }) => api.post(`/groups/${groupId}/members`, { peer_id: peerId }),
    onMutate: async ({ groupId, peerId }) => {
      await qc.cancelQueries({ queryKey: QUERY_KEYS.members(groupId) })
      const previousMembers = qc.getQueryData(QUERY_KEYS.members(groupId))
      // Find peer details for optimistic update
      const peer = allPeers?.find(p => p.id === peerId)
      if (peer) {
        qc.setQueryData(QUERY_KEYS.members(groupId), old => [...(old || []), peer])
      }
      return { previousMembers }
    },
    onError: (err, vars, context) => {
      qc.setQueryData(QUERY_KEYS.members(vars.groupId), context.previousMembers)
      setFormErrors({ _general: err.message })
    },
    onSettled: (data, err, vars) => { 
      qc.invalidateQueries({ queryKey: QUERY_KEYS.members(vars.groupId) })
      qc.invalidateQueries({ queryKey: QUERY_KEYS.groups() })
    },
  })

  const deleteMemberMutation = useMutation({
    mutationFn: ({ groupId, peerId }) => api.delete(`/groups/${groupId}/members/${peerId}`),
    onMutate: async ({ groupId, peerId }) => {
      await qc.cancelQueries({ queryKey: QUERY_KEYS.members(groupId) })
      const previousMembers = qc.getQueryData(QUERY_KEYS.members(groupId))
      qc.setQueryData(QUERY_KEYS.members(groupId), old => old?.filter(m => m.id !== peerId) || [])
      return { previousMembers }
    },
    onError: (err, vars, context) => {
      qc.setQueryData(QUERY_KEYS.members(vars.groupId), context.previousMembers)
      showToast(err.message, 'error')
    },
    onSettled: (data, err, vars) => { 
      qc.invalidateQueries({ queryKey: QUERY_KEYS.members(vars.groupId) })
      qc.invalidateQueries({ queryKey: QUERY_KEYS.groups() })
    },
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    if (editGroup) updateMutation.mutate({ id: editGroup.id, data: formData })
    else createMutation.mutate(formData)
  }

  const handleAddPeer = () => {
    if (!selectedPeerId) return
    addMemberMutation.mutate({ groupId: editGroup.id, peerId: selectedPeerId })
    setSelectedPeerId(null)
  }

  const handleRemovePeer = (peerId) => {
    deleteMemberMutation.mutate({ groupId: editGroup.id, peerId })
  }

  if (isLoading) return <TableSkeleton rows={3} columns={4} />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-light-neutral">Groups</h1>
          <p className="text-gray-600 dark:text-amber-muted">Organize peers into logical groups for policy targeting</p>
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
          <button onClick={openAdd} className="flex items-center gap-2 px-4 py-2 bg-purple-active hover:bg-purple-700 text-white text-sm font-medium rounded-lg">
            <Plus className="w-4 h-4" /> New Group
          </button>
        </div>
      </div>

      {/* Search Bar */}
      {groups?.length > 0 && (
        <div className="flex items-center gap-2">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search groups..."
              className="w-full pl-9 pr-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral placeholder-gray-400"
            />
          </div>
        </div>
      )}

      {!groups?.length ? (
        <EmptyState title="No groups yet" message="Create groups to organize peers for policy targeting." action="New Group" onAction={openAdd} />
      ) : !filteredGroups.length ? (
        <EmptyState title="No matching groups" message="Try a different search term." />
      ) : (
        <DataTable columns={[
          { 
            key: 'name', 
            label: (
              <button 
                type="button"
                onClick={() => handleSort('name')}
className="flex items-center hover:text-runic-600 dark:hover:text-purple-active"
>
Name
                <SortIndicator columnKey="name" />
              </button>
            ), 
            render: (g) => (
              <div className="flex items-center gap-2">
                {g.is_system && <Lock className="w-4 h-4 text-gray-400" />}
                <span className="font-medium text-gray-900 dark:text-light-neutral">{g.name}</span>
              </div>
            )
          },
          { 
            key: 'peers', 
            label: (
              <button 
                type="button"
                onClick={() => handleSort('peers')}
className="flex items-center hover:text-runic-600 dark:hover:text-purple-active"
>
Peers
                <SortIndicator columnKey="peers" />
              </button>
            ),
            render: (g) => (
<div className="flex items-center gap-1.5 px-2 py-1 bg-gray-100 dark:bg-charcoal-darkest rounded text-sm">
<Users className="w-4 h-4 text-gray-500" />
<span className="text-gray-900 dark:text-light-neutral">{g.peer_count || 0}</span>
</div>
            )
          },
          { 
            key: 'policies', 
            label: (
              <button 
                type="button"
                onClick={() => handleSort('policies')}
className="flex items-center hover:text-runic-600 dark:hover:text-purple-active"
>
Policies
                <SortIndicator columnKey="policies" />
              </button>
            ),
            render: (g) => (
<div className="flex items-center gap-1.5 px-2 py-1 bg-gray-100 dark:bg-charcoal-darkest rounded text-sm">
<Shield className="w-4 h-4 text-gray-500" />
<span className="text-gray-900 dark:text-light-neutral">{g.policy_count || 0}</span>
</div>
            )
          },
          { 
            key: 'actions', 
            label: 'Actions', 
            render: (g) => (
              <div className="flex items-center gap-2">
<button
                  onClick={(e) => { e.stopPropagation(); openEdit(g) }}
                  className={`p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded ${g.is_system ? 'text-gray-400 cursor-not-allowed' : ''}`}
                  disabled={g.is_system}
                  title="Edit"
                >
                  <Pencil className="w-4 h-4 text-gray-500" />
                </button>
                {!g.is_system && (
                  <button onClick={(e) => { e.stopPropagation(); setDeleteTarget(g) }} className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded">
                    <Trash2 className="w-4 h-4 text-red-500" />
                  </button>
                )}
              </div>
            )
          },
        ]} data={filteredGroups} />
      )}

  {/* Add/Edit Modal */}
  {modalOpen && (
  <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
        onKeyDown={(e) => {
          if (e.key === 'Escape') {
            closeModal()
          }
        }}
      >
<div ref={modalRef} className="bg-white dark:bg-charcoal-dark rounded-xl shadow-xl w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
<div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border flex items-center justify-between">
<h3 id="modal-title" className="text-lg font-semibold text-gray-900 dark:text-light-neutral">
                {editGroup ? `Edit Group: ${editGroup.name}` : 'New Group'}
              </h3>
              <button onClick={closeModal} className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded">
                <X className="w-5 h-5 text-gray-500" />
              </button>
            </div>
            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div>
<label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Name</label>
<input
type="text"
value={formData.name}
onChange={e => setFormData(d => ({ ...d, name: e.target.value }))}
required
disabled={editGroup?.is_system}
className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral disabled:opacity-50 disabled:cursor-not-allowed"
/>
              </div>
              <div>
<label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Description</label>
<textarea
value={formData.description}
onChange={e => setFormData(d => ({ ...d, description: e.target.value }))}
rows={2}
disabled={editGroup?.is_system}
className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral disabled:opacity-50 disabled:cursor-not-allowed"
/>
              </div>

              {/* Tag-based Member Management */}
              {editGroup && (
<div className="border-t border-gray-200 dark:border-gray-border pt-4">
<label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-2">Members</label>
                  
{membersLoading ? (
              <div className="flex flex-wrap gap-2">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="animate-pulse bg-gray-200 dark:bg-charcoal-darkest h-8 w-24 rounded-full" />
                ))}
              </div>
            ) : (
                    <div className="space-y-3">
                      {/* Member Tags */}
                      <div className="flex flex-wrap gap-2 min-h-[40px] p-3 border border-gray-300 dark:border-gray-border rounded-lg bg-gray-50 dark:bg-charcoal-darkest">
                        {members.length === 0 ? (
                          <span className="text-sm text-gray-500 italic">No members in this group</span>
                        ) : (
                          members.map(m => (
<span
key={m.id}
className="px-3 py-1 bg-gray-100 dark:bg-charcoal-darkest rounded-full text-sm flex items-center gap-2"
>
<span className="text-gray-900 dark:text-light-neutral">{m.hostname || m.ip_address}</span>
{!editGroup?.is_system && (
<button
type="button"
onClick={() => handleRemovePeer(m.id)}
className="hover:bg-gray-200 dark:hover:bg-charcoal-dark rounded-full p-0.5"
                                  disabled={deleteMemberMutation.isPending}
                                >
                                  <X className="w-3 h-3 text-gray-500 hover:text-red-500" />
                                </button>
                              )}
                            </span>
                          ))
                        )}
                      </div>

{/* Add Peer Dropdown */}
                {!editGroup?.is_system && (
                  <div className="flex items-end gap-2">
                    {peerOptions.length === 0 ? (
                      <div className="flex-1 text-sm text-gray-500 italic text-center py-2">
                        All peers are already in this group.
                      </div>
                    ) : (
                      <>
                        <div className="flex-1">
                          <SearchableSelect
                            options={peerOptions}
                            value={selectedPeerId}
                            onChange={setSelectedPeerId}
                            placeholder="Add Peer to group..."
                          />
                        </div>
                        <button
                          type="button"
                          onClick={handleAddPeer}
                          disabled={!selectedPeerId || addMemberMutation.isPending}
                          className="px-3 py-2 text-sm font-medium text-white bg-purple-active hover:bg-purple-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          Add
                        </button>
                      </>
                    )}
                  </div>
                )}
                    </div>
                  )}
                </div>
              )}

              <InlineError message={formErrors._general} />
              <div className="flex justify-end gap-3 pt-2">
<button type="button" onClick={closeModal} className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-light-neutral bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-lg hover:bg-gray-50 dark:hover:bg-charcoal-darkest">Cancel</button>
<button type="submit" className="px-4 py-2 text-sm font-medium text-white bg-purple-active hover:bg-purple-700 rounded-lg">{editGroup ? 'Save Changes' : 'Create Group'}</button>
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
