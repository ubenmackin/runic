import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { UserPlus, Trash2, Pencil, X, Key, Copy, CheckCircle } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { isValidEmail } from '../utils/validation'
import { useToastContext } from '../hooks/ToastContext'
import TableSkeleton from '../components/TableSkeleton'
import { useAuthStore } from '../store'
import { useAuth } from '../hooks/useAuth'
import PageHeader from '../components/PageHeader'
import { useCrudMutations } from '../hooks/useCrudMutations'
import { useFocusTrap } from '../hooks/useFocusTrap'
import SearchableSelect from '../components/SearchableSelect'

const ROLE_OPTIONS = [
  { value: 'viewer', label: 'Viewer' },
  { value: 'editor', label: 'Editor' },
  { value: 'admin', label: 'Admin' },
]

export default function Users() {
  const { showToast } = useToastContext()
  const currentUsername = useAuthStore(s => s.username)
  const { isAdmin } = useAuth()
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [formUsername, setFormUsername] = useState('')
  const [formPassword, setFormPassword] = useState('')
  const [formConfirmPassword, setFormConfirmPassword] = useState('')
  const [formEmail, setFormEmail] = useState('')
  const [formRole, setFormRole] = useState('viewer')
  const [showEditModal, setShowEditModal] = useState(false)
  const [editTarget, setEditTarget] = useState(null)
  const [formEditEmail, setFormEditEmail] = useState('')
  const [formEditRole, setFormEditRole] = useState('viewer')
  const [formEditPassword, setFormEditPassword] = useState('')
  const [formEditConfirmPassword, setFormEditConfirmPassword] = useState('')

  const qc = useQueryClient()
  const [tokensUser, setTokensUser] = useState(null)
  const [showTokenCreateModal, setShowTokenCreateModal] = useState(false)
  const [tokenName, setTokenName] = useState('')
  const [tokenExpiryDays, setTokenExpiryDays] = useState('30')
  const [createdToken, setCreatedToken] = useState(null)
  const [revokeTarget, setRevokeTarget] = useState(null)

  const createModalRef = useRef(null)
  const editModalRef = useRef(null)
  const deleteModalRef = useRef(null)
  const tokensModalRef = useRef(null)
  const tokenCreateModalRef = useRef(null)
  const tokenCreatedModalRef = useRef(null)
  const tokenRevokeModalRef = useRef(null)

  useFocusTrap(createModalRef, showCreateModal)
  useFocusTrap(editModalRef, showEditModal)
  useFocusTrap(deleteModalRef, !!deleteTarget)
  useFocusTrap(tokensModalRef, !!tokensUser && !showTokenCreateModal && !createdToken && !revokeTarget)
  useFocusTrap(tokenCreateModalRef, showTokenCreateModal)
  useFocusTrap(tokenCreatedModalRef, !!createdToken)
  useFocusTrap(tokenRevokeModalRef, !!revokeTarget)

  const { data: users, isLoading, error } = useQuery({
    queryKey: QUERY_KEYS.users(),
    queryFn: ({ signal }) => api.get('/users', signal),
  })

  const list = Array.isArray(users) ? users : users?.users ?? []

  const resetForm = () => {
    setFormUsername('')
    setFormPassword('')
    setFormConfirmPassword('')
    setFormEmail('')
    setFormRole('viewer')
  }

  const { createMutation, updateMutation, deleteMutation } = useCrudMutations({
    apiPath: '/users',
    queryKey: QUERY_KEYS.users(),
    onCreateSuccess: () => {
      setShowCreateModal(false)
      resetForm()
      showToast('User created successfully', 'success')
    },
    onUpdateSuccess: () => {
      setShowEditModal(false)
      setEditTarget(null)
      showToast('User updated successfully', 'success')
    },
    onDeleteSuccess: () => {
      setDeleteTarget(null)
      showToast('User deleted successfully', 'success')
    },
    setFormErrors: null,
    showToast,
  })

  const handleCreateUser = (e) => {
    e.preventDefault()
    if (formEmail && !isValidEmail(formEmail)) {
      showToast('Please enter a valid email address', 'error')
      return
    }
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

  const { data: tokensData, isLoading: tokensLoading } = useQuery({
    queryKey: QUERY_KEYS.userTokensFor(tokensUser?.id),
    queryFn: ({ signal }) => api.get(`/users/${tokensUser.id}/tokens`, signal),
    enabled: !!tokensUser && isAdmin,
  })
  const tokenList = Array.isArray(tokensData) ? tokensData : tokensData?.tokens ?? tokensData?.items ?? []

  const createTokenMutation = useMutation({
    mutationFn: ({ userId, payload }) => api.post(`/users/${userId}/tokens`, payload),
    onSuccess: (data) => {
      setCreatedToken(data)
      setShowTokenCreateModal(false)
      setTokenName('')
      setTokenExpiryDays('30')
      qc.invalidateQueries({ queryKey: QUERY_KEYS.userTokensFor(tokensUser?.id) })
      showToast('API token created', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const revokeTokenMutation = useMutation({
    mutationFn: ({ userId, tokenId }) => api.delete(`/users/${userId}/tokens/${tokenId}`),
    onSuccess: () => {
      setRevokeTarget(null)
      qc.invalidateQueries({ queryKey: QUERY_KEYS.userTokensFor(tokensUser?.id) })
      showToast('API token revoked', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const handleCreateToken = (e) => {
    e.preventDefault()
    const name = tokenName.trim()
    if (!name) {
      showToast('Token name is required', 'error')
      return
    }
    if (name.length > 100) {
      showToast('Token name must be 100 characters or fewer', 'error')
      return
    }
    const days = parseInt(tokenExpiryDays, 10)
    if (Number.isNaN(days) || days < 0 || days > 365) {
      showToast('Expiry must be between 0 and 365 days', 'error')
      return
    }
    createTokenMutation.mutate({ userId: tokensUser.id, payload: { name, expires_in_days: days } })
  }

  const copyTokenToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text)
      showToast('Copied to clipboard', 'success')
    } catch {
      showToast('Failed to copy to clipboard', 'error')
    }
  }

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Users"
          description="Manage user accounts for the Runic control plane"
        />
        <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none">
          <div className="p-6 text-center">
            <p className="text-red-500 dark:text-red-400 font-medium mb-2">Failed to load users</p>
            <p className="text-gray-500 dark:text-amber-muted text-sm">{error.message}</p>
          </div>
        </div>
      </div>
    )
  }

  if (isLoading) return <TableSkeleton rows={3} columns={4} />

  return (
    <div className="space-y-6">
      <PageHeader
        title="Users"
        description="Manage user accounts for the Runic control plane"
        actions={
          isAdmin && (
            <button
              onClick={() => setShowCreateModal(true)}
              className="inline-flex items-center gap-2 px-4 py-2 bg-purple-active hover:bg-purple-600 text-white rounded-none border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all"
            >
              <UserPlus className="w-5 h-5" />
              Create User
            </button>
          )
        }
      />

      {!list.length ? (
        <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none">
          <div className="p-6 text-center text-gray-500 dark:text-amber-muted">
            <p>No users found. Create your first user to get started.</p>
          </div>
        </div>
      ) : (
        <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-border">
<thead className="bg-gray-50 dark:bg-charcoal-darkest">
<tr>
<th className="px-6 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">Username</th>
<th className="px-6 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">Email</th>
<th className="px-6 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">Role</th>
<th className="px-6 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">Actions</th>
</tr>
</thead>
<tbody className="divide-y divide-gray-200 dark:divide-gray-border">
{list.map((user) => (
<tr key={user.id}>
<td className="px-6 py-2 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-light-neutral">{user.username}</td>
<td className="px-6 py-2 whitespace-nowrap text-sm text-gray-500 dark:text-amber-primary">{user.email || '—'}</td>
<td className="px-6 py-2 whitespace-nowrap text-sm text-gray-500 dark:text-amber-primary">{user.role || 'viewer'}</td>
<td className="px-6 py-2 whitespace-nowrap text-sm">
                    {isAdmin && (
                      <button
                        onClick={() => {
                          setEditTarget(user)
                          setFormEditEmail(user.email || '')
                          setFormEditRole(user.role || 'viewer')
                          setFormEditPassword('')
                          setFormEditConfirmPassword('')
                          setShowEditModal(true)
                        }}
                        className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none mr-1"
                      >
                        <Pencil className="w-4 h-4 text-gray-500 dark:text-amber-muted" />
                      </button>
                    )}
                    {isAdmin && (
                      <button
                        onClick={() => {
                          setTokensUser(user)
                          setCreatedToken(null)
                          setRevokeTarget(null)
                        }}
                        className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none mr-1"
                        title={`Manage API tokens for ${user.username}`}
                      >
                        <Key className="w-4 h-4 text-gray-500 dark:text-amber-muted" />
                      </button>
                    )}
                    {isAdmin && user.username !== currentUsername && (
<button
          onClick={() => setDeleteTarget(user)}
          className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none"
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

  {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" role="dialog" aria-modal="true" tabIndex="-1" autoFocus onKeyDown={(e) => { if (e.key === 'Escape') { setShowCreateModal(false) } }}>
          <div ref={createModalRef} className="bg-white dark:bg-charcoal-dark rounded-none p-6 max-w-md w-full mx-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">Create User</h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded"
              >
                <X className="w-5 h-5 text-gray-500" />
              </button>
            </div>
            <form onSubmit={handleCreateUser} className="space-y-4">
              <div>
                <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                  Username <span className="text-red-500">*</span>
                </label>
                <input
                  id="username"
                  type="text"
                  required
                  value={formUsername}
                  onChange={(e) => setFormUsername(e.target.value)}
className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-active focus:border-transparent"
        placeholder="Enter username"
                />
              </div>
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                  Password <span className="text-red-500">*</span>
                </label>
                <input
                  id="password"
                  type="password"
                  required
                  minLength={8}
                  value={formPassword}
                  onChange={(e) => setFormPassword(e.target.value)}
className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-active focus:border-transparent"
        placeholder="Enter password"
                />
                <p className="mt-1 text-xs text-gray-500 dark:text-amber-muted">Minimum 8 characters</p>
              </div>
              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                  Confirm Password <span className="text-red-500">*</span>
                </label>
                <input
                  id="confirmPassword"
                  type="password"
                  required
                  minLength={8}
                  value={formConfirmPassword}
                  onChange={(e) => setFormConfirmPassword(e.target.value)}
className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-active focus:border-transparent"
        placeholder="Confirm password"
                />
              </div>
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                  Email
                </label>
<input
        id="email"
        type="email"
        value={formEmail}
        onChange={(e) => setFormEmail(e.target.value)}
        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-active focus:border-transparent"
        placeholder="Enter email (optional)"
      />
              </div>
                <div>
                  <label htmlFor="role" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                    Role
                  </label>
                  <SearchableSelect
                    options={ROLE_OPTIONS}
                    value={formRole}
                    onChange={(v) => setFormRole(v)}
                    placeholder="Select role"
                  />
                </div>
              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setShowCreateModal(false)
                    resetForm()
                  }}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border rounded-none text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
className="flex-1 px-4 py-2 bg-purple-active hover:bg-purple-600 text-white rounded-none disabled:opacity-50 border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all"
>
{createMutation.isPending ? 'Creating...' : 'Create'}
                </button>
              </div>
            </form>
          </div>
    </div>
  )}

  {deleteTarget && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" role="dialog" aria-modal="true">
          <div ref={deleteModalRef} className="bg-white dark:bg-charcoal-dark rounded-none p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral mb-2">Delete User</h3>
        <p className="text-gray-600 dark:text-amber-muted mb-6">
          Are you sure you want to delete user &quot;{deleteTarget.username}&quot;? This action cannot be undone.
        </p>
            <div className="flex gap-3">
              <button
                onClick={() => setDeleteTarget(null)}
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border rounded-none text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
              >
                Cancel
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteTarget.id)}
                disabled={deleteMutation.isPending}
                className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-none disabled:opacity-50"
              >
                {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
    </div>
  )}

  {showEditModal && editTarget && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" role="dialog" aria-modal="true" tabIndex="-1" autoFocus onKeyDown={(e) => { if (e.key === 'Escape') { setShowEditModal(false) } }}>
          <div ref={editModalRef} className="bg-white dark:bg-charcoal-dark rounded-none p-6 max-w-md w-full mx-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">Edit User</h3>
<button
          onClick={() => setShowEditModal(false)}
          className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none"
        >
                <X className="w-5 h-5 text-gray-500" />
              </button>
            </div>
            <form
              onSubmit={(e) => {
                e.preventDefault()
                if (formEditEmail && !isValidEmail(formEditEmail)) {
                  showToast('Please enter a valid email address', 'error')
                  return
                }
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
                <label htmlFor="editEmail" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                  Email
                </label>
                <input
                  id="editEmail"
                  type="email"
                  value={formEditEmail}
                  onChange={(e) => setFormEditEmail(e.target.value)}
className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-active focus:border-transparent"
        placeholder="Enter email (optional)"
                />
              </div>
              <div>
                <label htmlFor="editRole" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                  Role
                </label>
                <SearchableSelect
                  options={ROLE_OPTIONS}
                  value={formEditRole}
                  onChange={(v) => setFormEditRole(v)}
                  placeholder="Select role"
                />
              </div>
              <div>
                <label htmlFor="editPassword" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                  New Password
                </label>
                <input
                  id="editPassword"
                  type="password"
                  minLength={8}
                  value={formEditPassword}
                  onChange={(e) => setFormEditPassword(e.target.value)}
className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-active focus:border-transparent"
        placeholder="Leave blank to keep current password"
                />
                <p className="mt-1 text-xs text-gray-500 dark:text-amber-muted">Minimum 8 characters. Leave blank to keep current password.</p>
              </div>
              <div>
                <label htmlFor="editConfirmPassword" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                  Confirm New Password
                </label>
                <input
                  id="editConfirmPassword"
                  type="password"
                  minLength={8}
                  value={formEditConfirmPassword}
                  onChange={(e) => setFormEditConfirmPassword(e.target.value)}
className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-active focus:border-transparent"
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
                    setFormEditRole('viewer')
                    setFormEditPassword('')
                    setFormEditConfirmPassword('')
                  }}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border rounded-none text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={updateMutation.isPending}
className="flex-1 px-4 py-2 bg-purple-active hover:bg-purple-600 text-white rounded-none disabled:opacity-50 border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all"
>
{updateMutation.isPending ? 'Updating...' : 'Update'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

  {tokensUser && !showTokenCreateModal && !createdToken && !revokeTarget && (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" role="dialog" aria-modal="true" tabIndex="-1" autoFocus onKeyDown={(e) => { if (e.key === 'Escape') { setTokensUser(null) } }}>
      <div ref={tokensModalRef} className="bg-white dark:bg-charcoal-dark rounded-none p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">API Tokens — {tokensUser.username}</h3>
          <button
            onClick={() => setTokensUser(null)}
            className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>
        <p className="text-sm text-gray-600 dark:text-amber-muted mb-4">
          Tokens are shown masked. The full token is displayed only once at creation. Use these for automation (e.g. llm_agent).
        </p>
        <div className="flex justify-end mb-4">
          <button
            onClick={() => setShowTokenCreateModal(true)}
            className="inline-flex items-center gap-2 px-4 py-2 bg-purple-active hover:bg-purple-600 text-white rounded-none border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all text-sm"
          >
            <Key className="w-4 h-4" />
            Create Token
          </button>
        </div>
        {tokensLoading ? (
          <p className="text-sm text-gray-500 dark:text-amber-muted text-center py-6">Loading tokens...</p>
        ) : !tokenList.length ? (
          <div className="p-6 text-center text-gray-500 dark:text-amber-muted text-sm">
            <p>No API tokens for this user yet. Create one to get started.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-border">
              <thead className="bg-gray-50 dark:bg-charcoal-darkest">
                <tr>
                  <th className="px-4 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">Name</th>
                  <th className="px-4 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">Token</th>
                  <th className="px-4 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">Expires</th>
                  <th className="px-4 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">Last Used</th>
                  <th className="px-4 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-border">
                {tokenList.map((tok) => (
                  <tr key={tok.id}>
                    <td className="px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-light-neutral">{tok.name}</td>
                    <td className="px-4 py-2 whitespace-nowrap text-sm font-mono text-gray-500 dark:text-amber-primary">{tok.display || `${tok.prefix}...`}</td>
                    <td className="px-4 py-2 whitespace-nowrap text-sm text-gray-500 dark:text-amber-primary">{tok.expires_at || 'Never'}</td>
                    <td className="px-4 py-2 whitespace-nowrap text-sm text-gray-500 dark:text-amber-primary">{tok.last_used_at || '—'}</td>
                    <td className="px-4 py-2 whitespace-nowrap text-sm">
                      <button
                        onClick={() => setRevokeTarget(tok)}
                        className="p-1.5 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none"
                        title="Revoke token"
                      >
                        <Trash2 className="w-4 h-4 text-red-500" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )}

  {showTokenCreateModal && tokensUser && (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" role="dialog" aria-modal="true" tabIndex="-1" autoFocus onKeyDown={(e) => { if (e.key === 'Escape') { setShowTokenCreateModal(false) } }}>
      <div ref={tokenCreateModalRef} className="bg-white dark:bg-charcoal-dark rounded-none p-6 max-w-md w-full mx-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">Create Token — {tokensUser.username}</h3>
          <button
            onClick={() => setShowTokenCreateModal(false)}
            className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>
        <form onSubmit={handleCreateToken} className="space-y-4">
          <div>
            <label htmlFor="tokenName" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
              Name <span className="text-red-500">*</span>
            </label>
            <input
              id="tokenName"
              type="text"
              required
              maxLength={100}
              value={tokenName}
              onChange={(e) => setTokenName(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-active focus:border-transparent"
              placeholder="e.g. ci-runner"
            />
          </div>
          <div>
            <label htmlFor="tokenExpiry" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
              Expiry
            </label>
            <select
              id="tokenExpiry"
              value={tokenExpiryDays}
              onChange={(e) => setTokenExpiryDays(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral focus:outline-none focus:ring-2 focus:ring-purple-active"
            >
              <option value="0">Never expires</option>
              <option value="7">7 days</option>
              <option value="30">30 days</option>
              <option value="90">90 days</option>
              <option value="365">365 days</option>
            </select>
          </div>
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={() => setShowTokenCreateModal(false)}
              className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border rounded-none text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createTokenMutation.isPending}
              className="flex-1 px-4 py-2 bg-purple-active hover:bg-purple-600 text-white rounded-none disabled:opacity-50 border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all"
            >
              {createTokenMutation.isPending ? 'Creating...' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )}

  {createdToken && (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" role="dialog" aria-modal="true" tabIndex="-1" autoFocus onKeyDown={(e) => { if (e.key === 'Escape') { setCreatedToken(null) } }}>
      <div ref={tokenCreatedModalRef} className="bg-white dark:bg-charcoal-dark rounded-none p-6 max-w-lg w-full mx-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Token Created
        </h3>
        <div className="space-y-4">
          <div className="flex items-center gap-3 text-green-600 dark:text-green-400">
            <CheckCircle className="w-6 h-6" />
            <span className="font-medium">Token created successfully</span>
          </div>
          <div className="p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-none">
            <p className="text-sm text-yellow-800 dark:text-yellow-300 font-medium">
              Copy this token now — it will never be shown again!
            </p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-muted mb-1">
              Full Token
            </label>
            <div className="flex items-center gap-2">
              <div className="flex-1 p-3 bg-gray-100 dark:bg-charcoal-darkest rounded font-mono text-sm text-gray-700 dark:text-amber-primary break-all">
                {createdToken.full_token}
              </div>
              <button
                onClick={() => copyTokenToClipboard(createdToken.full_token)}
                className="p-2 bg-blue-600 hover:bg-blue-700 text-white rounded-none shrink-0"
                title="Copy to clipboard"
              >
                <Copy className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
        <div className="mt-6">
          <button
            onClick={() => setCreatedToken(null)}
            className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-none"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  )}

  {revokeTarget && tokensUser && (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" role="dialog" aria-modal="true">
      <div ref={tokenRevokeModalRef} className="bg-white dark:bg-charcoal-dark rounded-none p-6 max-w-md w-full mx-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral mb-2">Revoke Token</h3>
        <p className="text-gray-600 dark:text-amber-muted mb-6">
          Are you sure you want to revoke token &quot;{revokeTarget.name}&quot; for user &quot;{tokensUser.username}&quot;? This action cannot be undone.
        </p>
        <div className="flex gap-3">
          <button
            onClick={() => setRevokeTarget(null)}
            className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border rounded-none text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
          >
            Cancel
          </button>
          <button
            onClick={() => revokeTokenMutation.mutate({ userId: tokensUser.id, tokenId: revokeTarget.id })}
            disabled={revokeTokenMutation.isPending}
            className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-none disabled:opacity-50"
          >
            {revokeTokenMutation.isPending ? 'Revoking...' : 'Revoke'}
          </button>
        </div>
      </div>
    </div>
  )}
    </div>
  )
}
