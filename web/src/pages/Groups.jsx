import { useState, useRef, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Users, Shield, X, RefreshCw, Pencil, AlertTriangle, Layers, ChevronDown, ChevronUp } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useCrudModal } from '../hooks/useCrudModal'
import { useTableSort } from '../hooks/useTableSort'
import { usePagination } from '../hooks/usePagination'
import { useToastContext } from '../hooks/ToastContext'
import { useFocusTrap } from '../hooks/useFocusTrap'
import { useTableFilter } from '../hooks/useTableFilter'
import { useCrudMutations } from '../hooks/useCrudMutations'
import { useAuth } from '../hooks/useAuth'
import ConfirmModal from '../components/ConfirmModal'
import SearchableSelect from '../components/SearchableSelect'
import EmptyState from '../components/EmptyState'

import TableSkeleton from '../components/TableSkeleton'
import SortIndicator from '../components/SortIndicator'
import Pagination from '../components/Pagination'
import SearchFilterPanel from '../components/SearchFilterPanel'
import PageHeader from '../components/PageHeader'

export default function Groups() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const { canEdit } = useAuth()
  const { modalOpen, editItem: editGroup, setEditItem: setEditGroup, form: formData, setForm: setFormData, setFormForEdit, handleOpenAdd, handleCancel, setModalOpen } = useCrudModal({ name: '', description: '' })
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [conflictError, setConflictError] = useState(null)
  const [_formErrors, setFormErrors] = useState({})

  const { sortConfig, handleSort } = useTableSort('groups', { key: 'name', direction: 'asc' })

  const [searchQuery, setSearchQuery] = useState('')

  const [showSystemGroups, setShowSystemGroups] = useState(false)

  const [showPendingDeletes, setShowPendingDeletes] = useState(false)

  const [selectedPeerId, setSelectedPeerId] = useState(null)
  const [isManualRefreshing, setIsManualRefreshing] = useState(false)

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

  useFocusTrap(modalRef, modalOpen)

  const { data: groups, isLoading, refetch } = useQuery({
    queryKey: QUERY_KEYS.groups(),
    queryFn: () => api.get('/groups'),
  })

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

  const { data: allPeers } = useQuery({
    queryKey: QUERY_KEYS.peers(),
    queryFn: () => api.get('/peers'),
    enabled: modalOpen && !!editGroup,
  })

  const availablePeers = (allPeers || []).filter(
    peer => !members.some(m => m.id === peer.id)
  )
  const peerOptions = availablePeers.map(p => ({
    value: p.id,
    label: p.hostname ? `${p.hostname} - ${p.ip_address}` : p.ip_address,
  }))

  const systemGroups = (groups || []).filter(g => g.is_system)
  const userGroups = (groups || []).filter(g => !g.is_system)

  const visibleGroups = showPendingDeletes ? userGroups : userGroups.filter(g => !g.is_pending_delete)

  const filteredGroups = useTableFilter(visibleGroups, searchQuery, sortConfig, {
    filterFn: (g, query) => {
      return (
        g.name.toLowerCase().includes(query) ||
        String(g.peer_count || 0).includes(query) ||
        String(g.policy_count || 0).includes(query)
      )
    },
    secondarySortKey: 'name',
  })

  const {
    paginatedData: paginatedGroups,
    totalPages,
    showingRange: groupsShowingRange,
    page: groupsPage,
    rowsPerPage: groupsRowsPerPage,
    onPageChange: setGroupsPage,
    onRowsPerPageChange: setGroupsRowsPerPage,
    totalItems: groupsTotal
  } = usePagination(filteredGroups, 'groups')

  const { createMutation, updateMutation, deleteMutation } = useCrudMutations({
    apiPath: '/groups',
    queryKey: QUERY_KEYS.groups(),
    additionalInvalidations: [['pending-changes']],
    onCreateSuccess: closeModal,
    onUpdateSuccess: closeModal,
    onDeleteSuccess: () => setDeleteTarget(null),
    setFormErrors,
    showToast,
  })

  const handleDeleteConfirm = async () => {
    try {
      await deleteMutation.mutateAsync(deleteTarget.id)
    } catch (err) {
      if (err.status === 409 && err.data?.policies) {
        setConflictError({
          groupName: deleteTarget.name,
          policies: err.data.policies,
        })
        setDeleteTarget(null)
      }
    }
  }

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
      qc.invalidateQueries({ queryKey: ['pending-changes'] })
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
      qc.invalidateQueries({ queryKey: ['pending-changes'] })
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
      <PageHeader
        title="Groups"
        description="Organize peers into logical groups for policy targeting"
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
                <Plus className="w-4 h-4" /> New Group
              </button>
            )}
          </>
        }
      />

      {/* System Groups Panel */}
      {systemGroups.length > 0 && (
        <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none overflow-hidden">
          <button
            type="button"
            onClick={() => setShowSystemGroups(!showSystemGroups)}
            className="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-gray-50 dark:hover:bg-charcoal-darkest transition-colors"
          >
            <div className="flex items-center gap-2">
              <Layers className="w-5 h-5 text-blue-500" />
              <span className="font-medium text-gray-900 dark:text-light-neutral">System Groups</span>
              <span className="text-xs text-gray-500 dark:text-amber-muted">(Automatically managed)</span>
            </div>
            {showSystemGroups ? (
              <ChevronUp className="w-5 h-5 text-gray-500" />
            ) : (
              <ChevronDown className="w-5 h-5 text-gray-500" />
            )}
          </button>
          {showSystemGroups && (
            <div className="px-4 pb-4 border-t border-gray-200 dark:border-gray-border">
              <div className="mt-3 space-y-2 text-sm">
                {systemGroups.map((g) => (
                  <div key={g.id} className="flex items-start gap-2">
                    <div>
                      <span className="font-medium text-gray-700 dark:text-amber-primary">{g.name}:</span>
                      <span className="text-gray-600 dark:text-amber-muted ml-1">{g.description}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Search Bar and Rows per page */}
      {userGroups?.length > 0 && (
        <SearchFilterPanel
          storageKey="groups-search-filters-expanded"
          searchTerm={searchQuery}
          onSearchChange={setSearchQuery}
          onClearSearch={() => setSearchQuery('')}
          searchPlaceholder="Search groups..."
          rowsPerPage={groupsRowsPerPage}
          onRowsPerPageChange={setGroupsRowsPerPage}
        >
          {userGroups?.some(g => g.is_pending_delete) && (
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
      )}

      {!userGroups?.length ? (
        <EmptyState title="No user groups yet" message="Create groups to organize peers for policy targeting." action="New Group" onAction={openAdd} />
      ) : !filteredGroups.length ? (
        <EmptyState title="No matching groups" message="Try a different search term." />
      ) : (
        <div className="border border-gray-200 dark:border-gray-border overflow-hidden">
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
                    <button type="button" onClick={() => handleSort('peers')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                      Peers <SortIndicator columnKey="peers" sortConfig={sortConfig} />
                    </button>
                  </th>
                  <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                    <button type="button" onClick={() => handleSort('policies')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                      Policies <SortIndicator columnKey="policies" sortConfig={sortConfig} />
                    </button>
                  </th>
                  <th className="text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-border">
                {paginatedGroups.map((group) => (
                  <tr key={group.id} className="">
                    <td className="px-4 py-1">
                      <span className="font-medium text-gray-900 dark:text-light-neutral">
                        {group.name}
                        {group.is_pending_delete && (
                          <span className="ml-2 px-2 py-1 text-xs bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300 rounded-none">
                            Pending Delete
                          </span>
                        )}
                      </span>
                    </td>
                    <td className="px-4 py-1">
                      <div className="flex items-center gap-1.5 px-2 py-1 bg-gray-100 dark:bg-charcoal-darkest rounded-none text-sm">
                        <Users className="w-4 h-4 text-gray-500" />
                        <span className="text-gray-900 dark:text-light-neutral">{group.peer_count || 0}</span>
                      </div>
                    </td>
                    <td className="px-4 py-1">
                      <div className="flex items-center gap-1.5 px-2 py-1 bg-gray-100 dark:bg-charcoal-darkest rounded-none text-sm">
                        <Shield className="w-4 h-4 text-gray-500" />
                        <span className="text-gray-900 dark:text-light-neutral">{group.policy_count || 0}</span>
                      </div>
                    </td>
                    <td className="px-4 py-1">
                      <div className="flex items-center gap-2">
                        {canEdit && (
                          <button
                            onClick={(e) => { e.stopPropagation(); openEdit(group) }}
                            className={`p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none ${(group.is_system || group.is_pending_delete) ? 'text-gray-400 cursor-not-allowed opacity-50' : ''}`}
                            disabled={group.is_system || group.is_pending_delete}
                            title={group.is_pending_delete ? "Cannot edit soft-deleted groups" : group.is_system ? "System groups cannot be edited" : "Edit"}
                          >
                            <Pencil className={`w-4 h-4 ${(group.is_system || group.is_pending_delete) ? 'text-gray-400' : 'text-gray-900 dark:text-white'}`} />
                          </button>
                        )}
                        {canEdit && (
                          <button
                            onClick={(e) => { e.stopPropagation(); !group.is_system && !group.is_pending_delete && setDeleteTarget(group) }}
                            disabled={group.is_system || group.is_pending_delete}
                            className={`p-1 rounded-none ${(group.is_system || group.is_pending_delete) ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-100 dark:hover:bg-charcoal-darkest'}`}
                            title={group.is_pending_delete ? "Cannot delete soft-deleted groups" : group.is_system ? "System groups cannot be deleted" : "Delete"}
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

          <Pagination showingRange={groupsShowingRange} page={groupsPage} totalPages={totalPages} onPageChange={setGroupsPage} totalItems={groupsTotal} />
        </div>
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
          <div ref={modalRef} className="bg-white dark:bg-charcoal-dark rounded-none shadow-none w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border flex items-center justify-between">
              <h3 id="modal-title" className="text-lg font-semibold text-gray-900 dark:text-light-neutral">
                {editGroup ? `Edit Group: ${editGroup.name}` : 'New Group'}
              </h3>
              <button onClick={closeModal} className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none">
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
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral disabled:opacity-50 disabled:cursor-not-allowed"
                />
              </div>

              {/* Tag-based Member Management */}
              {editGroup && (
                <div className="border-t border-gray-200 dark:border-gray-border pt-4">
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-2">Members</label>

                  {membersLoading ? (
                    <div className="flex flex-wrap gap-2">
                      {[1, 2, 3].map((i) => (
                        <div key={i} className="animate-pulse bg-gray-200 dark:bg-charcoal-darkest h-8 w-24" />
                      ))}
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {/* Member Tags */}
                      <div className="flex flex-wrap gap-2 min-h-[40px] p-3 border border-gray-300 dark:border-gray-border rounded-none bg-gray-50 dark:bg-charcoal-darkest">
                        {members.length === 0 ? (
                          <span className="text-sm text-gray-500 italic">No members in this group</span>
                        ) : (
                          members.map(m => (
                            <span
                              key={m.id}
                              className="px-3 py-1 bg-gray-100 dark:bg-charcoal-darkest rounded-none text-sm flex items-center gap-2"
                            >
                              <span className="text-gray-900 dark:text-light-neutral">{m.hostname || m.ip_address}</span>
                              {!editGroup?.is_system && (
                                <button
                                  type="button"
                                  onClick={() => handleRemovePeer(m.id)}
                                  className="hover:bg-gray-200 dark:hover:bg-charcoal-dark rounded-none p-0.5"
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
                                className="px-3 py-2 text-sm font-bold uppercase text-white bg-purple-active hover:bg-purple-600 rounded-none disabled:opacity-50 disabled:cursor-not-allowed border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all"
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

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Description</label>
                <textarea
                  value={formData.description}
                  onChange={e => setFormData(d => ({ ...d, description: e.target.value }))}
                  rows={2}
                  disabled={editGroup?.is_system}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral disabled:opacity-50 disabled:cursor-not-allowed"
                />
              </div>

              <div className="flex justify-end gap-3 pt-4">
                <button
                  type="button"
                  onClick={closeModal}
                  className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-none hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending || updateMutation.isPending}
                  className="px-4 py-2 text-sm font-bold uppercase text-white bg-purple-active hover:bg-purple-600 rounded-none disabled:opacity-50 disabled:cursor-not-allowed border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all"
                >
                  {editGroup ? 'Update' : 'Create'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {deleteTarget && (
        <ConfirmModal
          title="Delete Group"
          message={`Delete group "${deleteTarget.name}"?`}
          onConfirm={handleDeleteConfirm}
          onCancel={() => setDeleteTarget(null)}
          danger
        />
      )}

      {/* Conflict Error Modal */}
      {conflictError && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none w-full max-w-md mx-4">
            <div className="p-6">
              <div className="flex items-center gap-3 mb-4">
                <AlertTriangle className="w-6 h-6 text-amber-500" />
                <h3 className="text-lg font-semibold">Cannot Delete Group</h3>
              </div>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                The group &quot;{conflictError.groupName}&quot; is used by the following policies:
              </p>
              <ul className="list-disc list-inside mb-4 text-gray-700 dark:text-gray-300">
                {conflictError.policies.map(p => (
                  <li key={p.id}>{p.name}</li>
                ))}
              </ul>
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                Remove this group from those policies before deleting it.
              </p>
              <button
                onClick={() => setConflictError(null)}
                className="w-full px-4 py-2 bg-gray-100 dark:bg-charcoal-darkest rounded-none"
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
