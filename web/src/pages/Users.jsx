import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { UserPlus, Trash2, Pencil } from 'lucide-react'
import { api } from '../api/client'
import { useToastContext } from '../hooks/ToastContext'
import TableSkeleton from '../components/TableSkeleton'
import { useAuthStore } from '../store'

export default function Users() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const currentUsername = useAuthStore(s => s.username)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [formUsername, setFormUsername] = useState('')
  const [formPassword, setFormPassword] = useState('')
  const [formConfirmPassword, setFormConfirmPassword] = useState('')
  const [formEmail, setFormEmail] = useState('')
  const [formRole, setFormRole] = useState('user')
  const [showEditModal, setShowEditModal] = useState(false)
  const [editTarget, setEditTarget] = useState(null)
const [formEditEmail, setFormEditEmail] = useState('')
const [formEditRole, setFormEditRole] = useState('user')
const [formEditPassword, setFormEditPassword] = useState('')
const [formEditConfirmPassword, setFormEditConfirmPassword] = useState('')

  const { data: users, isLoading, error } = useQuery({
    queryKey: ['users'],
    queryFn: () => api.get('/users'),
  })

  // Show error state if query failed
  if (error) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Users</h1>
            <p className="text-gray-600 dark:text-gray-400">Manage user accounts for the Runic control plane</p>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
          <div className="p-6 text-center">
            <p className="text-red-500 dark:text-red-400 font-medium mb-2">Failed to load users</p>
            <p className="text-gray-500 dark:text-gray-400 text-sm">{error.message}</p>
          </div>
        </div>
      </div>
    )
  }

  const createMutation = useMutation({
    mutationFn: (data) => api.post('/users', data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] })
      setShowCreateModal(false)
      resetForm()
      showToast('User created successfully', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => api.delete(`/users/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] })
      setDeleteTarget(null)
      showToast('User deleted successfully', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }) => api.put(`/users/${id}`, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] })
      setShowEditModal(false)
      setEditTarget(null)
      showToast('User updated successfully', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const resetForm = () => {
    setFormUsername('')
    setFormPassword('')
    setFormConfirmPassword('')
    setFormEmail('')
    setFormRole('user')
  }

  const handleCreateUser = (e) => {
    e.preventDefault()
    if (formPassword !== formConfirmPassword) {
      showToast('Passwords do not match', 'error')
      return
    }
    createMutation.mutate({
      username: formUsername,
      password: formPassword,
      email: formEmail || undefined,
      role: formRole,
    })
  }

  if (isLoading) return <TableSkeleton rows={3} columns={4} />

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Users</h1>
          <p className="text-gray-600 dark:text-gray-400">Manage user accounts for the Runic control plane</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="inline-flex items-center gap-2 px-4 py-2 bg-runic-600 hover:bg-runic-700 text-white rounded-lg"
        >
          <UserPlus className="w-5 h-5" />
          Create User
        </button>
      </div>

      {!users?.length ? (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
          <div className="p-6 text-center text-gray-500 dark:text-gray-400">
            <p>No users found. Create your first user to get started.</p>
          </div>
        </div>
      ) : (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-900">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Username</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Email</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Role</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {users.map((user) => (
                <tr key={user.id}>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">{user.username}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">{user.email || '—'}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">{user.role || 'user'}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
              <button
                onClick={() => {
                  setEditTarget(user)
                  setFormEditEmail(user.email || '')
                  setFormEditRole(user.role || 'user')
                  setFormEditPassword('')
                  setFormEditConfirmPassword('')
                  setShowEditModal(true)
                }}
                className="p-1.5 hover:bg-gray-100 dark:hover:bg-gray-700 rounded mr-1"
              >
                <Pencil className="w-4 h-4 text-gray-500 dark:text-gray-400" />
              </button>
              {user.username !== currentUsername && (
                <button
                  onClick={() => setDeleteTarget(user)}
                  className="p-1.5 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
                >
                  <Trash2 className="w-4 h-4 text-red-500" />
                </button>
              )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Create user modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Create User</h3>
            <form onSubmit={handleCreateUser} className="space-y-4">
              <div>
                <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Username <span className="text-red-500">*</span>
                </label>
                <input
                  id="username"
                  type="text"
                  required
                  value={formUsername}
                  onChange={(e) => setFormUsername(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-runic-500 focus:border-transparent"
                  placeholder="Enter username"
                />
              </div>
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Password <span className="text-red-500">*</span>
                </label>
                <input
                  id="password"
                  type="password"
                  required
                  minLength={8}
                  value={formPassword}
                  onChange={(e) => setFormPassword(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-runic-500 focus:border-transparent"
                  placeholder="Enter password"
                />
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Minimum 8 characters</p>
              </div>
              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Confirm Password <span className="text-red-500">*</span>
                </label>
                <input
                  id="confirmPassword"
                  type="password"
                  required
                  minLength={8}
                  value={formConfirmPassword}
                  onChange={(e) => setFormConfirmPassword(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-runic-500 focus:border-transparent"
                  placeholder="Confirm password"
                />
              </div>
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Email
                </label>
                <input
                  id="email"
                  type="email"
                  value={formEmail}
                  onChange={(e) => setFormEmail(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-runic-500 focus:border-transparent"
                  placeholder="Enter email (optional)"
                />
              </div>
              <div>
                <label htmlFor="role" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Role
                </label>
                <select
                  id="role"
                  value={formRole}
                  onChange={(e) => setFormRole(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-runic-500 focus:border-transparent"
                >
                  <option value="user">user</option>
                  <option value="admin">admin</option>
                </select>
              </div>
              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setShowCreateModal(false)
                    resetForm()
                  }}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="flex-1 px-4 py-2 bg-runic-600 hover:bg-runic-700 text-white rounded-lg disabled:opacity-50"
                >
                  {createMutation.isPending ? 'Creating...' : 'Create'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteTarget && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Delete User</h3>
            <p className="text-gray-600 dark:text-gray-400 mb-6">
              Are you sure you want to delete user "{deleteTarget.username}"? This action cannot be undone.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setDeleteTarget(null)}
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Cancel
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteTarget.id)}
                disabled={deleteMutation.isPending}
                className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg disabled:opacity-50"
              >
                {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit user modal */}
      {showEditModal && editTarget && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Edit User</h3>
<form
onSubmit={(e) => {
e.preventDefault()
// Email format validation
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
if (formEditEmail && !emailRegex.test(formEditEmail)) {
showToast('Please enter a valid email address', 'error')
return
}
// Password confirmation validation
if (formEditPassword && formEditPassword !== formEditConfirmPassword) {
showToast('Passwords do not match', 'error')
return
}
updateMutation.mutate({
id: editTarget.id,
data: {
email: formEditEmail || undefined,
role: formEditRole,
password: formEditPassword || undefined,
},
})
}}
className="space-y-4"
>
              <div>
                <label htmlFor="editEmail" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Email
                </label>
                <input
                  id="editEmail"
                  type="email"
                  value={formEditEmail}
                  onChange={(e) => setFormEditEmail(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-runic-500 focus:border-transparent"
                  placeholder="Enter email (optional)"
                />
              </div>
              <div>
                <label htmlFor="editRole" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Role
                </label>
                <select
                  id="editRole"
                  value={formEditRole}
                  onChange={(e) => setFormEditRole(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-runic-500 focus:border-transparent"
                >
                  <option value="user">user</option>
                  <option value="admin">admin</option>
                </select>
              </div>
              <div>
                <label htmlFor="editPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  New Password
                </label>
                <input
                  id="editPassword"
                  type="password"
                  minLength={8}
                  value={formEditPassword}
                  onChange={(e) => setFormEditPassword(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-runic-500 focus:border-transparent"
                  placeholder="Leave blank to keep current password"
                />
<p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Minimum 8 characters. Leave blank to keep current password.</p>
</div>
<div>
<label htmlFor="editConfirmPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
Confirm New Password
</label>
<input
id="editConfirmPassword"
type="password"
minLength={8}
value={formEditConfirmPassword}
onChange={(e) => setFormEditConfirmPassword(e.target.value)}
className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-runic-500 focus:border-transparent"
placeholder="Confirm new password"
/>
</div>
<div className="flex gap-3 pt-2">
                <button
type="button"
onClick={() => {
setShowEditModal(false)
setEditTarget(null)
setFormEditEmail('')
setFormEditRole('user')
setFormEditPassword('')
setFormEditConfirmPassword('')
}}
className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={updateMutation.isPending}
                  className="flex-1 px-4 py-2 bg-runic-600 hover:bg-runic-700 text-white rounded-lg disabled:opacity-50"
                >
                  {updateMutation.isPending ? 'Updating...' : 'Update'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
