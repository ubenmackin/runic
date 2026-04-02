import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Lock, Trash2, Plus, Shield, Key } from 'lucide-react'
import { api } from '../api/client'
import { useToastContext } from '../hooks/ToastContext'
import { useFocusTrap } from '../hooks/useFocusTrap'
import { useAuth } from '../hooks/useAuth'
import PageHeader from '../components/PageHeader'

export default function Settings() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const { isAdmin } = useAuth()
  const [showDeleteModal, setShowDeleteModal] = useState(null)
  const [showCreateModal, setShowCreateModal] = useState(null)
  const deleteModalRef = useRef(null)
  const createModalRef = useRef(null)
  useFocusTrap(deleteModalRef, showDeleteModal !== null)
  useFocusTrap(createModalRef, showCreateModal !== null)

  const { data: keys, isLoading } = useQuery({
    queryKey: ['setup-keys'],
    queryFn: () => api.get('/setup-keys'),
    enabled: isAdmin,
  })

  const deleteMutation = useMutation({
    mutationFn: (keyType) => api.delete(`/setup-keys/${keyType}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['setup-keys'] })
      setShowDeleteModal(null)
      showToast('Key deleted successfully', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const createMutation = useMutation({
    mutationFn: (keyType) => api.post(`/setup-keys/${keyType}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['setup-keys'] })
      setShowCreateModal(null)
      showToast('Key created successfully', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const handleDelete = (keyType) => {
    deleteMutation.mutate(keyType)
  }

  const handleCreate = (keyType) => {
    createMutation.mutate(keyType)
  }

  const getKeyData = (keyType) => {
    if (!keys) return null
    return keys.find(k => k.type === keyType)
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description="Configure your Runic installation"
      />

      {!isAdmin ? (
        <div className="bg-white dark:bg-charcoal-dark rounded-lg shadow">
          <div className="p-12 text-center">
            <Lock className="w-12 h-12 text-gray-400 dark:text-gray-500 mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-gray-900 dark:text-light-neutral mb-2">Access Denied</h2>
            <p className="text-gray-600 dark:text-amber-muted">
              Only administrators can access Settings. Please contact an admin if you need to make changes.
            </p>
          </div>
        </div>
      ) : (
        <>

      {/* JWT Secret Section */}
      <div className="bg-white dark:bg-charcoal-dark rounded-lg shadow">
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Shield className="w-5 h-5 text-blue-500" />
              <h2 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">JWT Secret</h2>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setShowDeleteModal('jwt-secret')}
                className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded-lg"
              >
                <Trash2 className="w-4 h-4" />
                Delete
              </button>
              <button
                onClick={() => setShowCreateModal('jwt-secret')}
                className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-purple-active hover:bg-purple-active/80 text-white rounded-lg"
              >
                <Plus className="w-4 h-4" />
                Create New
              </button>
            </div>
          </div>
          <p className="text-gray-600 dark:text-amber-muted text-sm">
            JWT Secret is used for user authentication tokens. Changing this will log out all users.
          </p>
          <div className="mt-4 p-3 bg-gray-100 dark:bg-charcoal-darkest rounded font-mono text-sm text-gray-700 dark:text-amber-primary">
            {isLoading ? 'Loading...' : getKeyData('jwt-secret')?.exists ? '•••••••••••••••••••••••••••••••••••••••••' : 'No key configured'}
          </div>
        </div>
      </div>

      {/* Agent JWT Secret Section */}
      <div className="bg-white dark:bg-charcoal-dark rounded-lg shadow">
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Key className="w-5 h-5 text-green-500" />
              <h2 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">Agent JWT Secret</h2>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setShowDeleteModal('agent-jwt-secret')}
                className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded-lg"
              >
                <Trash2 className="w-4 h-4" />
                Delete
              </button>
              <button
                onClick={() => setShowCreateModal('agent-jwt-secret')}
                className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-purple-active hover:bg-purple-active/80 text-white rounded-lg"
              >
                <Plus className="w-4 h-4" />
                Create New
              </button>
            </div>
          </div>
          <p className="text-gray-600 dark:text-amber-muted text-sm">
            Agent JWT Secret is used to authenticate agents with the control plane. Changing this will disconnect all agents.
          </p>
          <div className="mt-4 p-3 bg-gray-100 dark:bg-charcoal-darkest rounded font-mono text-sm text-gray-700 dark:text-amber-primary">
            {isLoading ? 'Loading...' : getKeyData('agent-jwt-secret')?.exists ? '•••••••••••••••••••••••••••••••••••••••••' : 'No key configured'}
          </div>
        </div>
      </div>

      {/* Delete Confirmation Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div ref={deleteModalRef} className="bg-white dark:bg-charcoal-dark rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
              Delete {showDeleteModal === 'jwt-secret' ? 'JWT Secret' : 'Agent JWT Secret'}?
            </h3>
            <p className="text-gray-600 dark:text-amber-muted mb-6">
              This action cannot be undone and will {showDeleteModal === 'jwt-secret' ? 'log out all users' : 'disconnect all agents'}.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowDeleteModal(null)}
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border rounded-lg text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDelete(showDeleteModal)}
                disabled={deleteMutation.isPending}
                className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg disabled:opacity-50"
              >
                {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create New Confirmation Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div ref={createModalRef} className="bg-white dark:bg-charcoal-dark rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
              Create New {showCreateModal === 'jwt-secret' ? 'JWT Secret' : 'Agent JWT Secret'}?
            </h3>
            <p className="text-gray-600 dark:text-amber-muted mb-6">
              This will generate a new key. {showCreateModal === 'jwt-secret' ? 'All users will be logged out.' : 'All agents will be disconnected.'}
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowCreateModal(null)}
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border rounded-lg text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
              >
                Cancel
              </button>
              <button
                onClick={() => handleCreate(showCreateModal)}
                disabled={createMutation.isPending}
                className="flex-1 px-4 py-2 bg-purple-active hover:bg-purple-active/80 text-white rounded-lg disabled:opacity-50"
              >
                {createMutation.isPending ? 'Creating...' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}
        </>
      )}
    </div>
  )
}
