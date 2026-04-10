import { useState, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Lock, Trash2, Plus, Shield, Key, Database, HardDrive } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
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
  const [logSettings, setLogSettings] = useState(null)
  const [retentionDays, setRetentionDays] = useState(30)
  const [customDays, setCustomDays] = useState('')
  const [useCustomRetention, setUseCustomRetention] = useState(false)
  const [showClearLogsModal, setShowClearLogsModal] = useState(false)
  const deleteModalRef = useRef(null)
  const createModalRef = useRef(null)
  useFocusTrap(deleteModalRef, showDeleteModal !== null)
  useFocusTrap(createModalRef, showCreateModal !== null)

  const { data: keys, isLoading } = useQuery({
    queryKey: QUERY_KEYS.setupKeys(),
    queryFn: () => api.get('/setup-keys'),
    enabled: isAdmin,
  })

  const { data: logSettingsData, refetch: refetchLogSettings } = useQuery({
    queryKey: QUERY_KEYS.logSettings(),
    queryFn: () => api.get('/settings/logs'),
    enabled: isAdmin,
  })

  const deleteMutation = useMutation({
    mutationFn: (keyType) => api.delete(`/setup-keys/${keyType}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QUERY_KEYS.setupKeys() })
      setShowDeleteModal(null)
      showToast('Key deleted successfully', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const createMutation = useMutation({
    mutationFn: (keyType) => api.post(`/setup-keys/${keyType}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QUERY_KEYS.setupKeys() })
      setShowCreateModal(null)
      showToast('Key created successfully', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  useEffect(() => {
    if (logSettingsData) {
      setLogSettings(logSettingsData)
      setRetentionDays(logSettingsData.retention_days)
      // Define standard retention values
      const standardValues = [0, 1, 14, 30, 90, 365, -1]
      const isNonStandard = !standardValues.includes(logSettingsData.retention_days)
      if (isNonStandard) {
        // Initialize customDays and show input for non-standard values
        setCustomDays(String(logSettingsData.retention_days))
        setUseCustomRetention(true)
      } else {
        setUseCustomRetention(false)
      }
    }
  }, [logSettingsData])

  const updateLogSettingsMutation = useMutation({
    mutationFn: (days) => api.put('/settings/logs', { retention_days: days }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QUERY_KEYS.logSettings() })
      showToast('Log retention updated', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const clearLogsMutation = useMutation({
    mutationFn: () => api.delete('/logs'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QUERY_KEYS.logSettings() })
      qc.invalidateQueries({ queryKey: QUERY_KEYS.dashboardStats() })
      qc.invalidateQueries({ queryKey: QUERY_KEYS.blockedLogs24h() })
      setShowClearLogsModal(false)
      showToast('All logs cleared', 'success')
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
          {/* Log Management Section */}
          <div className="bg-white dark:bg-charcoal-dark rounded-lg shadow">
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <Database className="w-5 h-5 text-purple-500" />
                  <h2 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">Log Management</h2>
                </div>
                <button
                  onClick={() => setShowClearLogsModal(true)}
                  className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded-lg"
                >
                  <Trash2 className="w-4 h-4" />
                  Clear All Logs
                </button>
              </div>
      {/* Stats */}
      <div className="flex gap-6 mb-4">
        <div className="flex items-center gap-2">
          <HardDrive className="w-4 h-4 text-gray-400" />
          <span className="text-sm text-gray-600 dark:text-amber-muted">
            {logSettings?.log_count?.toLocaleString() || 0} logs
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-600 dark:text-amber-muted">
            ~{logSettings?.estimated_size_mb?.toLocaleString() || 0} MB
          </span>
        </div>
      </div>
      {/* Logs Database Path */}
      {logSettings?.logs_db_path && (
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
            Logs Database Path
          </label>
          <div className="p-2 bg-gray-100 dark:bg-charcoal-darkest rounded font-mono text-sm text-gray-700 dark:text-amber-muted">
            {logSettings.logs_db_path}
          </div>
        </div>
      )}
              {/* Retention Setting */}
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-2">
                  Retention Period
                </label>
                <div className="flex gap-2 items-center">
                  <select
                    value={useCustomRetention ? 'custom' : (retentionDays === -1 ? 'unlimited' : retentionDays === 0 ? '0' : retentionDays === 1 ? '1' : retentionDays === 14 ? '14' : retentionDays === 30 ? '30' : retentionDays === 90 ? '90' : retentionDays === 365 ? '365' : 'custom')}
                    onChange={(e) => {
                      const val = e.target.value
                      if (val === 'custom') {
                        setUseCustomRetention(true)
                      } else {
                        setUseCustomRetention(false)
                        if (val === 'unlimited') {
                          setRetentionDays(-1)
                          updateLogSettingsMutation.mutate(-1)
                        } else {
                          const days = parseInt(val)
                          setRetentionDays(days)
                          updateLogSettingsMutation.mutate(days)
                        }
                      }
                    }}
                    className="px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                  >
                    <option value="0">Disabled (no logging)</option>
                    <option value="1">1 Day</option>
                    <option value="14">14 Days</option>
                    <option value="30">30 Days</option>
                    <option value="90">90 Days</option>
                    <option value="365">365 Days</option>
                    <option value="unlimited">Unlimited</option>
                    <option value="custom">Custom...</option>
                  </select>
                  {(useCustomRetention || (retentionDays > 0 && ![0, 1, 14, 30, 90, 365].includes(retentionDays))) && (
                    <input
                      type="number"
                      min="1"
                      max="9999"
                      value={customDays}
                      onChange={(e) => {
                        const val = parseInt(e.target.value) || 1
                        setCustomDays(String(val))
                        setRetentionDays(Math.min(9999, Math.max(1, val)))
                      }}
                      onBlur={() => updateLogSettingsMutation.mutate(retentionDays)}
                      className="w-24 px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                    />
                  )}
                </div>
                <p className="text-xs text-gray-500 dark:text-amber-muted mt-1">
                  {retentionDays === -1
                    ? 'Logs will never be automatically deleted.'
                    : retentionDays === 0
                    ? 'Agents will not send logs to the control plane.'
                    : `Logs older than ${retentionDays} day${retentionDays !== 1 ? 's' : ''} will be automatically deleted.`}
                </p>
              </div>
            </div>
          </div>

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

          {/* Clear Logs Confirmation Modal */}
          {showClearLogsModal && (
            <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
              <div className="bg-white dark:bg-charcoal-dark rounded-lg p-6 max-w-md w-full mx-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                  Clear All Logs?
                </h3>
                <p className="text-gray-600 dark:text-amber-muted mb-6">
                  This will permanently delete all {logSettings?.log_count?.toLocaleString() || 0} firewall logs. This action cannot be undone.
                </p>
                <div className="flex gap-3">
                  <button
                    onClick={() => setShowClearLogsModal(false)}
                    className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border rounded-lg text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => clearLogsMutation.mutate()}
                    disabled={clearLogsMutation.isPending}
                    className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg disabled:opacity-50"
                  >
                    {clearLogsMutation.isPending ? 'Clearing...' : 'Clear All Logs'}
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
