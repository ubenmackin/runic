import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Trash2, Plus } from 'lucide-react'
import { api } from '../api/client'
import { useToastContext } from '../hooks/ToastContext'
import TableSkeleton from '../components/TableSkeleton'

export default function SetupKeys() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const [showDeleteModal, setShowDeleteModal] = useState(null)
  const [showCreateModal, setShowCreateModal] = useState(null)

  const { data: keys, isLoading } = useQuery({
    queryKey: ['setup-keys'],
    queryFn: () => api.get('/setup-keys'),
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

  if (isLoading) return <TableSkeleton rows={3} columns={2} />

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Setup Keys</h1>
        <p className="text-gray-600 dark:text-gray-400">Manage HMAC and JWT keys for securing your Runic installation</p>
      </div>

      {/* JWT Secret Section */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">JWT Secret</h2>
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
                className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg"
              >
                <Plus className="w-4 h-4" />
                Create New
              </button>
            </div>
          </div>
          <p className="text-gray-600 dark:text-gray-400 text-sm">
            JWT secret used for user authentication tokens. Changing this will invalidate all user sessions.
          </p>
          <div className="mt-4 p-3 bg-gray-100 dark:bg-gray-900 rounded font-mono text-sm text-gray-700 dark:text-gray-300">
            {getKeyData('jwt-secret') ? '•••••••••••••••••••••••••••••••••••••••••' : 'No key configured'}
          </div>
        </div>
      </div>

      {/* HMAC Key Section */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">HMAC Key</h2>
            <div className="flex gap-2">
              <button
                onClick={() => setShowDeleteModal('hmac-key')}
                className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded-lg"
              >
                <Trash2 className="w-4 h-4" />
                Delete
              </button>
              <button
                onClick={() => setShowCreateModal('hmac-key')}
                className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg"
              >
                <Plus className="w-4 h-4" />
                Create New
              </button>
            </div>
          </div>
          <p className="text-gray-600 dark:text-gray-400 text-sm">
            HMAC key for policy signing. Changing this will require all agents to be re-registered.
          </p>
          <div className="mt-4 p-3 bg-gray-100 dark:bg-gray-900 rounded font-mono text-sm text-gray-700 dark:text-gray-300">
            {getKeyData('hmac-key') ? '•••••••••••••••••••••••••••••••••••••••••' : 'No key configured'}
          </div>
        </div>
      </div>

      {/* Agent JWT Secret Section */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Agent JWT Secret</h2>
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
                className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg"
              >
                <Plus className="w-4 h-4" />
                Create New
              </button>
            </div>
          </div>
          <p className="text-gray-600 dark:text-gray-400 text-sm">
            JWT secret for agent authentication. Changing this will invalidate all agent connections.
          </p>
          <div className="mt-4 p-3 bg-gray-100 dark:bg-gray-900 rounded font-mono text-sm text-gray-700 dark:text-gray-300">
            {getKeyData('agent-jwt-secret') ? '•••••••••••••••••••••••••••••••••••••••••' : 'No key configured'}
          </div>
        </div>
      </div>

      {/* Delete Confirmation Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
              Delete {showDeleteModal === 'jwt-secret' ? 'JWT Secret' :
              showDeleteModal === 'hmac-key' ? 'HMAC Key' : 'Agent JWT Secret'}?
            </h3>
            <p className="text-gray-600 dark:text-gray-400 mb-6">
              This action cannot be undone and will break all active sessions.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowDeleteModal(null)}
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
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
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
              Create New {showCreateModal === 'jwt-secret' ? 'JWT Secret' :
              showCreateModal === 'hmac-key' ? 'HMAC Key' : 'Agent JWT Secret'}?
            </h3>
            <p className="text-gray-600 dark:text-gray-400 mb-6">
              This will generate a new key. The current key will still be available but may not be used.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowCreateModal(null)}
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Cancel
              </button>
              <button
                onClick={() => handleCreate(showCreateModal)}
                disabled={createMutation.isPending}
                className="flex-1 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg disabled:opacity-50"
              >
                {createMutation.isPending ? 'Creating...' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
