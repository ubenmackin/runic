import { useState, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Lock, Trash2, Plus, Shield, Key, Database, HardDrive, Bell, FileKey, ScrollText, Mail, Eye, EyeOff, Send, Loader } from 'lucide-react'
import { api, QUERY_KEYS, getSMTPConfig, updateSMTPConfig, testSMTP, getNotificationPrefs, updateNotificationPrefs } from '../api/client'
import { useToastContext } from '../hooks/ToastContext'
import { useFocusTrap } from '../hooks/useFocusTrap'
import { useAuth } from '../hooks/useAuth'
import PageHeader from '../components/PageHeader'
import AlertSettings from '../components/AlertSettings'
import {
  alertTypes,
  transformPrefsToBackend,
  transformPrefsFromBackend,
  transformSMTPFromBackend,
} from '../utils/settingsTransform'

export default function Settings() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const { isAdmin } = useAuth()
  const [activeTab, setActiveTab] = useState('alerts')
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

  // SMTP Config State
  const [smtpFormData, setSmtpFormData] = useState({
    host: '',
    port: 587,
    username: '',
    password: '',
    use_tls: true,
    from_address: '',
    enabled: false,
  })
  const [showPassword, setShowPassword] = useState(false)

  // Track if initial data has been loaded to prevent overwriting user edits on refetch
  const smtpLoadedRef = useRef(false)
  const prefsLoadedRef = useRef(false)

  const { data: smtpConfig, isLoading: smtpLoading } = useQuery({
    queryKey: QUERY_KEYS.smtpConfig(),
    queryFn: getSMTPConfig,
    enabled: isAdmin,
  })

  // Update form data when SMTP config loads (only on initial load)
  useEffect(() => {
    if (smtpConfig && !smtpLoadedRef.current) {
      setSmtpFormData(transformSMTPFromBackend(smtpConfig))
      smtpLoadedRef.current = true
    }
  }, [smtpConfig])

  const updateSmtpMutation = useMutation({
    mutationFn: updateSMTPConfig,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QUERY_KEYS.smtpConfig() })
      smtpLoadedRef.current = false // Allow next load to update form with saved data
      showToast('SMTP configuration updated', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const testEmailMutation = useMutation({
    mutationFn: testSMTP,
    onSuccess: () => {
      showToast('Test email sent successfully', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  // Notification Preferences State
  const [notificationPrefs, setNotificationPrefs] = useState(null)
  const [showQuietHours, setShowQuietHours] = useState(false)
  const [showDigest, setShowDigest] = useState(false)



  // Timezone options
  const timezones = [
    { value: 'UTC', label: 'UTC' },
    { value: 'America/New_York', label: 'Eastern (New York)' },
    { value: 'America/Chicago', label: 'Central (Chicago)' },
    { value: 'America/Denver', label: 'Mountain (Denver)' },
    { value: 'America/Los_Angeles', label: 'Pacific (Los Angeles)' },
    { value: 'Europe/London', label: 'London' },
    { value: 'Europe/Paris', label: 'Paris' },
    { value: 'Asia/Tokyo', label: 'Tokyo' },
    { value: 'Australia/Sydney', label: 'Sydney' },
  ]

  // Fetch user notification preferences (visible to all authenticated users)
  const { data: userPrefs, isLoading: userPrefsLoading, isError: userPrefsError } = useQuery({
    queryKey: QUERY_KEYS.notificationPrefs(),
    queryFn: getNotificationPrefs,
    retry: false,
  })

  // Update local state when preferences load - transform flat backend response to nested frontend structure
  // Only update on initial load to prevent overwriting user edits on refetch
  useEffect(() => {
    if (userPrefs && !prefsLoadedRef.current) {
      setNotificationPrefs(transformPrefsFromBackend(userPrefs))
      prefsLoadedRef.current = true
    }
  }, [userPrefs])

  // Update preferences mutation
  const updatePrefsMutation = useMutation({
    mutationFn: (prefs) => updateNotificationPrefs(transformPrefsToBackend(prefs)),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: QUERY_KEYS.notificationPrefs() })
      prefsLoadedRef.current = false // Allow next load to update form with saved data
      showToast('Notification preferences saved', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const handleToggleAlertType = (key) => {
    if (!notificationPrefs) return
    const newPrefs = {
      ...notificationPrefs,
      alert_types: {
        ...notificationPrefs.alert_types,
        [key]: !notificationPrefs.alert_types?.[key],
      },
    }
    setNotificationPrefs(newPrefs)
    updatePrefsMutation.mutate(newPrefs)
  }

  const handleQuietHoursChange = (field, value) => {
    if (!notificationPrefs) return
    const newPrefs = {
      ...notificationPrefs,
      quiet_hours: {
        ...notificationPrefs.quiet_hours,
        [field]: value,
      },
    }
    setNotificationPrefs(newPrefs)
    updatePrefsMutation.mutate(newPrefs)
  }

  const handleDigestChange = (field, value) => {
    if (!notificationPrefs) return
    const newPrefs = {
      ...notificationPrefs,
      daily_digest: {
        ...notificationPrefs.daily_digest,
        [field]: value,
      },
    }
    setNotificationPrefs(newPrefs)
    updatePrefsMutation.mutate(newPrefs)
  }

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

  // Helper component for Notification Preferences section
  const NotificationPreferencesSection = () => (
    <div className="bg-white dark:bg-charcoal-dark rounded-lg shadow">
      <div className="p-6">
        <div className="flex items-center gap-3 mb-2">
          <Bell className="w-5 h-5 text-purple-500" />
          <h2 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">Your Notification Preferences</h2>
        </div>
        <p className="text-sm text-gray-600 dark:text-amber-muted mb-6">
          Configure which alerts you receive
        </p>

        {userPrefsLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader className="w-6 h-6 animate-spin text-purple-500" />
          </div>
        ) : userPrefsError ? (
          <div className="text-center py-8">
            <p className="text-gray-600 dark:text-amber-muted">
              Please log in to configure notification preferences.
            </p>
          </div>
        ) : notificationPrefs && (
          <div className="space-y-6">
            {/* Alert Type Toggles */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-3">
                Alert Types
              </label>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                {alertTypes.map((type) => (
                  <div key={type.key} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id={`alert-type-${type.key}`}
                      checked={notificationPrefs.alert_types?.[type.key] ?? true}
                      onChange={() => handleToggleAlertType(type.key)}
                      className="w-4 h-4 text-purple-600 border-gray-300 dark:border-gray-border rounded focus:ring-purple-500"
                    />
                    <label
                      htmlFor={`alert-type-${type.key}`}
                      className="text-sm text-gray-700 dark:text-amber-primary cursor-pointer"
                    >
                      {type.label}
                    </label>
                  </div>
                ))}
              </div>
            </div>

            {/* Quiet Hours Section */}
            <div className="border-t border-gray-200 dark:border-gray-border pt-6">
              <button
                onClick={() => setShowQuietHours(!showQuietHours)}
                className="flex items-center justify-between w-full text-left"
              >
                <span className="text-sm font-medium text-gray-700 dark:text-amber-primary">
                  Quiet Hours
                </span>
                <span className={`transform transition-transform ${showQuietHours ? 'rotate-180' : ''}`}>
                  <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </span>
              </button>
              {showQuietHours && (
                <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id="quiet_hours_enabled"
                      checked={notificationPrefs.quiet_hours?.enabled ?? false}
                      onChange={(e) => handleQuietHoursChange('enabled', e.target.checked)}
                      className="w-4 h-4 text-purple-600 border-gray-300 dark:border-gray-border rounded focus:ring-purple-500"
                    />
                    <label htmlFor="quiet_hours_enabled" className="text-sm text-gray-700 dark:text-amber-primary">
                      Enable Quiet Hours
                    </label>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                      Start Time
                    </label>
                    <input
                      type="time"
                      value={notificationPrefs.quiet_hours?.start_time || '22:00'}
                      onChange={(e) => handleQuietHoursChange('start_time', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                      End Time
                    </label>
                    <input
                      type="time"
                      value={notificationPrefs.quiet_hours?.end_time || '08:00'}
                      onChange={(e) => handleQuietHoursChange('end_time', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                      Timezone
                    </label>
                    <select
                      value={notificationPrefs.quiet_hours?.timezone || 'UTC'}
                      onChange={(e) => handleQuietHoursChange('timezone', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                    >
                      {timezones.map((tz) => (
                        <option key={tz.value} value={tz.value}>
                          {tz.label}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              )}
            </div>

            {/* Daily Digest Section */}
            <div className="border-t border-gray-200 dark:border-gray-border pt-6">
              <button
                onClick={() => setShowDigest(!showDigest)}
                className="flex items-center justify-between w-full text-left"
              >
                <span className="text-sm font-medium text-gray-700 dark:text-amber-primary">
                  Daily Digest
                </span>
                <span className={`transform transition-transform ${showDigest ? 'rotate-180' : ''}`}>
                  <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </span>
              </button>
              {showDigest && (
                <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id="digest_enabled"
                      checked={notificationPrefs.daily_digest?.enabled ?? false}
                      onChange={(e) => handleDigestChange('enabled', e.target.checked)}
                      className="w-4 h-4 text-purple-600 border-gray-300 dark:border-gray-border rounded focus:ring-purple-500"
                    />
                    <label htmlFor="digest_enabled" className="text-sm text-gray-700 dark:text-amber-primary">
                      Enable Daily Digest
                    </label>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                      Digest Time
                    </label>
                    <input
                      type="time"
                      value={notificationPrefs.daily_digest?.time || '09:00'}
                      onChange={(e) => handleDigestChange('time', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                    />
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description="Configure your Runic installation"
      />

      {/* Tab Navigation - at the top for admins */}
      {isAdmin && (
        <div className="flex border-b border-gray-200 dark:border-gray-border">
          <button
            onClick={() => setActiveTab('alerts')}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'alerts'
                ? 'border-purple-active text-purple-active dark:text-purple-active'
                : 'border-transparent text-gray-600 dark:text-amber-muted hover:text-gray-900 dark:hover:text-light-neutral hover:border-gray-300 dark:hover:border-gray-border'
            }`}
          >
            <Bell className="w-4 h-4" />
            Alerts
          </button>
          <button
            onClick={() => setActiveTab('logs')}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'logs'
                ? 'border-purple-active text-purple-active dark:text-purple-active'
                : 'border-transparent text-gray-600 dark:text-amber-muted hover:text-gray-900 dark:hover:text-light-neutral hover:border-gray-300 dark:hover:border-gray-border'
            }`}
          >
            <ScrollText className="w-4 h-4" />
            Logs
          </button>
          <button
            onClick={() => setActiveTab('keys')}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'keys'
                ? 'border-purple-active text-purple-active dark:text-purple-active'
                : 'border-transparent text-gray-600 dark:text-amber-muted hover:text-gray-900 dark:hover:text-light-neutral hover:border-gray-300 dark:hover:border-gray-border'
            }`}
          >
            <FileKey className="w-4 h-4" />
            Keys
          </button>
        </div>
      )}

      {/* Non-admin: Show notification preferences at the top */}
      {!isAdmin && (
        <>
          <NotificationPreferencesSection />

          <div className="bg-white dark:bg-charcoal-dark rounded-lg shadow">
            <div className="p-12 text-center">
              <Lock className="w-12 h-12 text-gray-400 dark:text-gray-500 mx-auto mb-4" />
              <h2 className="text-xl font-semibold text-gray-900 dark:text-light-neutral mb-2">Access Denied</h2>
              <p className="text-gray-600 dark:text-amber-muted">
                Only administrators can access Settings. Please contact an admin if you need to make changes.
              </p>
            </div>
          </div>
        </>
      )}

      {/* Admin: Tab content */}
      {isAdmin && (
        <>
          {/* Tab Content */}
          {activeTab === 'alerts' && (
            <div className="space-y-6">
              {/* User Notification Preferences - inside Alerts tab for admins */}
              <NotificationPreferencesSection />

              {/* SMTP Configuration Section */}
              <div className="bg-white dark:bg-charcoal-dark rounded-lg shadow">
                <div className="p-6">
                  <div className="flex items-center gap-3 mb-6">
                    <Mail className="w-5 h-5 text-purple-500" />
                    <h2 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">SMTP Configuration</h2>
                  </div>

                  {smtpLoading ? (
                    <div className="flex items-center justify-center py-8">
                      <Loader className="w-6 h-6 animate-spin text-purple-500" />
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* SMTP Host */}
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                          SMTP Host
                        </label>
                        <input
                          type="text"
                          value={smtpFormData.host}
                          onChange={(e) => setSmtpFormData({ ...smtpFormData, host: e.target.value })}
                          placeholder="smtp.example.com"
                          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                        />
                      </div>

                      {/* SMTP Port */}
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                          SMTP Port
                        </label>
                        <input
                          type="number"
                          value={smtpFormData.port}
                          onChange={(e) => setSmtpFormData({ ...smtpFormData, port: parseInt(e.target.value) || 587 })}
                          defaultValue={587}
                          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                        />
                      </div>

                      {/* Username */}
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                          Username
                        </label>
                        <input
                          type="text"
                          value={smtpFormData.username}
                          onChange={(e) => setSmtpFormData({ ...smtpFormData, username: e.target.value })}
                          placeholder="username"
                          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                        />
                      </div>

                      {/* Password */}
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                          Password
                        </label>
                        <div className="relative">
                          <input
                            type={showPassword ? 'text' : 'password'}
                            value={smtpFormData.password}
                            onChange={(e) => setSmtpFormData({ ...smtpFormData, password: e.target.value })}
                            placeholder={smtpConfig?.password_set ? '••••••••' : 'Enter password'}
                            className="w-full px-3 py-2 pr-10 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                          />
                          <button
                            type="button"
                            onClick={() => setShowPassword(!showPassword)}
                            className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700 dark:hover:text-amber-muted"
                          >
                            {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                          </button>
                        </div>
                      </div>

                      {/* From Address */}
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                          From Address
                        </label>
                        <input
                          type="email"
                          value={smtpFormData.from_address}
                          onChange={(e) => setSmtpFormData({ ...smtpFormData, from_address: e.target.value })}
                          placeholder="alerts@example.com"
                          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                        />
                      </div>

                      {/* TLS and Enable toggles */}
                      <div className="flex items-center gap-6">
                        <div className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            id="use_tls"
                            checked={smtpFormData.use_tls}
                            onChange={(e) => setSmtpFormData({ ...smtpFormData, use_tls: e.target.checked })}
                            className="w-4 h-4 text-purple-600 border-gray-300 dark:border-gray-border rounded focus:ring-purple-500"
                          />
                          <label htmlFor="use_tls" className="text-sm text-gray-700 dark:text-amber-primary">
                            Use TLS
                          </label>
                        </div>
                        <div className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            id="smtp_enabled"
                            checked={smtpFormData.enabled}
                            onChange={(e) => setSmtpFormData({ ...smtpFormData, enabled: e.target.checked })}
                            className="w-4 h-4 text-purple-600 border-gray-300 dark:border-gray-border rounded focus:ring-purple-500"
                          />
                          <label htmlFor="smtp_enabled" className="text-sm text-gray-700 dark:text-amber-primary">
                            Enable SMTP
                          </label>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Action Buttons */}
                  <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-gray-200 dark:border-gray-border">
                    <button
                      onClick={() => testEmailMutation.mutate()}
                      disabled={testEmailMutation.isPending || !smtpFormData.enabled}
                      className="inline-flex items-center gap-2 px-4 py-2 text-sm border border-gray-300 dark:border-gray-border rounded-lg text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {testEmailMutation.isPending ? (
                        <Loader className="w-4 h-4 animate-spin" />
                      ) : (
                        <Send className="w-4 h-4" />
                      )}
                      Test Email
                    </button>
                    <button
                      onClick={() => updateSmtpMutation.mutate(smtpFormData)}
                      disabled={updateSmtpMutation.isPending}
                      className="inline-flex items-center gap-2 px-4 py-2 text-sm bg-purple-active hover:bg-purple-active/80 text-white rounded-lg disabled:opacity-50"
                    >
                      {updateSmtpMutation.isPending ? 'Saving...' : 'Save SMTP Settings'}
                    </button>
                  </div>
                </div>
              </div>

              {/* Alert Settings Component */}
              <div className="bg-white dark:bg-charcoal-dark rounded-lg shadow">
                <div className="p-6">
                  <AlertSettings />
                </div>
              </div>
            </div>
          )}

          {activeTab === 'logs' && (
            <div className="space-y-6">
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
            </div>
          )}

          {activeTab === 'keys' && (
            <div className="space-y-6">
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
            </div>
          )}

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
