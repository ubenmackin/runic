import { useState, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Lock, Trash2, Plus, Shield, Key, Database, HardDrive, Bell, FileKey, ScrollText, Mail, Eye, EyeOff, Send, Loader, Server } from 'lucide-react'
import { api, QUERY_KEYS, getSMTPConfig, updateSMTPConfig, testSMTP, getNotificationPrefs, updateNotificationPrefs, getAlertRules } from '../api/client'
import { useToastContext } from '../hooks/ToastContext'
import { useFocusTrap } from '../hooks/useFocusTrap'
import { useAuth } from '../hooks/useAuth'
import PageHeader from '../components/PageHeader'
import AlertSettings from '../components/AlertSettings'
import CollapsibleSection from '../components/CollapsibleSection'
import ToggleSwitch from '../components/ToggleSwitch'
import {
  alertTypes,
  transformPrefsToBackend,
  transformPrefsFromBackend,
  transformSMTPFromBackend,
} from '../utils/settingsTransform'
import { isValidPort } from '../utils/validation'
import {
  getSMTPSummary,
  getNotificationSummary,
  getAlertRulesSummary,
} from '../utils/settingsSummary'

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

  // Controlled expanded states for jump-to-section functionality
  const [emailExpanded, setEmailExpanded] = useState(undefined)
  const [notificationsExpanded, setNotificationsExpanded] = useState(undefined)
  const [alertRulesExpanded, setAlertRulesExpanded] = useState(undefined)

  // Jump to section handler
  const handleJumpToSection = (e) => {
    const sectionId = e.target.value
    if (!sectionId) return

    const el = document.getElementById(sectionId)
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' })

      // Expand the section after scrolling
        setTimeout(() => {
          switch (sectionId) {
          case 'email-section':
            setEmailExpanded(true)
            break
          case 'notifications-section':
            setNotificationsExpanded(true)
            break
          case 'alert-rules-section':
            setAlertRulesExpanded(true)
            break
          }
        }, 100)
  }

  e.target.value = ''
}
  useFocusTrap(deleteModalRef, showDeleteModal !== null)
  useFocusTrap(createModalRef, showCreateModal !== null)

  const { data: keys, isLoading } = useQuery({
    queryKey: QUERY_KEYS.setupKeys(),
    queryFn: () => api.get('/setup-keys'),
    enabled: isAdmin,
  })

  const { data: logSettingsData } = useQuery({
    queryKey: QUERY_KEYS.logSettings(),
    queryFn: () => api.get('/settings/logs'),
    enabled: isAdmin,
  })

  // SMTP Config State
  const [smtpFormData, setSmtpFormData] = useState({
    host: '',
    port: '587',
    username: '',
    password: '',
    use_tls: true,
    from_address: '',
    enabled: false,
  })
  const [showPassword, setShowPassword] = useState(false)
  const [portError, setPortError] = useState('')

// Port validation function (uses shared utility, returns error message for UI)
const validatePort = (value) => {
  if (value === '') {
    return 'Port must be a number'
  }
  if (!isValidPort(value)) {
    return 'Port must be 1-65535'
  }
  return ''
}

  const handlePortChange = (e) => {
  const value = e.target.value
  if (!/^\d*$/.test(value)) return
  if (value.length > 5) return
  setSmtpFormData({ ...smtpFormData, port: value })
    setPortError(validatePort(value))
  }

  // Track if initial data has been loaded to prevent overwriting user edits on refetch
  const smtpLoadedRef = useRef(false)
  const prefsLoadedRef = useRef(false)

const { data: smtpConfig, isLoading: smtpLoading } = useQuery({
  queryKey: QUERY_KEYS.smtpConfig(),
  queryFn: getSMTPConfig,
  enabled: isAdmin,
})

useEffect(() => {
    if (smtpConfig && !smtpLoadedRef.current) {
      const transformedData = transformSMTPFromBackend(smtpConfig)
      setSmtpFormData(transformedData)
      setPortError(validatePort(transformedData.port))
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

  const [instanceUrl, setInstanceUrl] = useState('')
	const { data: instanceSettings } = useQuery({
		queryKey: ['instance-settings'],
		queryFn: () => api.get('/settings/instance'),
  enabled: isAdmin,
  })

  useEffect(() => {
    if (instanceSettings?.url !== undefined) {
      setInstanceUrl(instanceSettings.url)
    }
  }, [instanceSettings])

  const updateInstanceMutation = useMutation({
    mutationFn: (url) => api.put('/settings/instance', { url }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['instance-settings'] })
      showToast('Instance URL saved', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  // Agent Version Settings
  const [latestAgentVersion, setLatestAgentVersion] = useState('')
  const [agentVersionIsDefault, setAgentVersionIsDefault] = useState(false)
  const agentVersionLoadedRef = useRef(false)

  const { data: agentVersionData } = useQuery({
    queryKey: ['agent-version-settings'],
    queryFn: () => api.get('/settings/agent-version'),
    enabled: isAdmin,
  })

  useEffect(() => {
    if (agentVersionData && !agentVersionLoadedRef.current) {
      setLatestAgentVersion(agentVersionData.latest_agent_version || '')
      setAgentVersionIsDefault(agentVersionData.is_default ?? false)
      agentVersionLoadedRef.current = true
    }
  }, [agentVersionData])

  const updateAgentVersionMutation = useMutation({
    mutationFn: (version) => api.put('/settings/agent-version', { latest_agent_version: version }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent-version-settings'] })
      qc.invalidateQueries({ queryKey: QUERY_KEYS.info() })
      agentVersionLoadedRef.current = false
      showToast('Agent version setting saved', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const { data: alertRules } = useQuery({
    queryKey: QUERY_KEYS.alertRules(),
    queryFn: getAlertRules,
    enabled: isAdmin,
  })

  const [notificationPrefs, setNotificationPrefs] = useState(null)
  const [showQuietHours, setShowQuietHours] = useState(undefined)
  const [showDigest, setShowDigest] = useState(undefined)
  const [unifiedTimezone, setUnifiedTimezone] = useState(null)

  const { data: userPrefs, isLoading: userPrefsLoading, isError: userPrefsError } = useQuery({
    queryKey: QUERY_KEYS.notificationPrefs(),
    queryFn: getNotificationPrefs,
    retry: false,
  })

  useEffect(() => {
    if (userPrefs && !prefsLoadedRef.current) {
      const transformedPrefs = transformPrefsFromBackend(userPrefs)
      setNotificationPrefs(transformedPrefs)

      setUnifiedTimezone(transformedPrefs.quiet_hours?.timezone || 'UTC')

      // Expand disclosure sections based on feature enabled status
      // Quiet Hours disclosure: open if quietHours.enabled is true
        const quietHoursEnabled = transformedPrefs.quiet_hours?.enabled ?? false
        setShowQuietHours(quietHoursEnabled)

        // Daily Digest disclosure: open if dailyDigest.enabled is true
        const digestEnabled = transformedPrefs.daily_digest?.enabled ?? false
        setShowDigest(digestEnabled)

      prefsLoadedRef.current = true
    }
  }, [userPrefs])

  const updatePrefsMutation = useMutation({
    mutationFn: (prefs) => updateNotificationPrefs(transformPrefsToBackend(prefs)),
    onSuccess: () => {
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

  // Handle unified timezone change - updates both quiet_hours and daily_digest
  const handleUnifiedTimezoneChange = (value) => {
    if (!notificationPrefs) return
    setUnifiedTimezone(value)
    const newPrefs = {
      ...notificationPrefs,
      quiet_hours: {
        ...notificationPrefs.quiet_hours,
        timezone: value,
      },
      daily_digest: {
        ...notificationPrefs.daily_digest,
        timezone: value,
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

      {isAdmin && (
        <div className="flex justify-center border-b border-gray-200 dark:border-gray-border">
          <div className="flex" role="tablist">
            <button
              role="tab"
              aria-selected={activeTab === 'alerts'}
              aria-controls="alerts-tab-content"
              onClick={() => setActiveTab('alerts')}
              className={`flex items-center gap-3 px-6 py-4 text-base font-medium transition-colors ${
                activeTab === 'alerts'
                  ? 'border-b-[3px] border-purple-active text-purple-active font-semibold'
                  : 'border-b-2 border-transparent text-gray-600 dark:text-amber-muted hover:text-gray-900 dark:hover:text-light-neutral hover:bg-gray-50 dark:hover:bg-charcoal-darkest/50'
              }`}
            >
              <Bell className="w-5 h-5" />
              Alerts
            </button>
            <button
              role="tab"
              aria-selected={activeTab === 'logs'}
              aria-controls="logs-tab-content"
              onClick={() => setActiveTab('logs')}
              className={`flex items-center gap-3 px-6 py-4 text-base font-medium transition-colors ${
                activeTab === 'logs'
                  ? 'border-b-[3px] border-purple-active text-purple-active font-semibold'
                  : 'border-b-2 border-transparent text-gray-600 dark:text-amber-muted hover:text-gray-900 dark:hover:text-light-neutral hover:bg-gray-50 dark:hover:bg-charcoal-darkest/50'
              }`}
            >
              <ScrollText className="w-5 h-5" />
              Logs
            </button>
            <button
              role="tab"
              aria-selected={activeTab === 'keys'}
              aria-controls="keys-tab-content"
              onClick={() => setActiveTab('keys')}
              className={`flex items-center gap-3 px-6 py-4 text-base font-medium transition-colors ${
                activeTab === 'keys'
                  ? 'border-b-[3px] border-purple-active text-purple-active font-semibold'
                  : 'border-b-2 border-transparent text-gray-600 dark:text-amber-muted hover:text-gray-900 dark:hover:text-light-neutral hover:bg-gray-50 dark:hover:bg-charcoal-darkest/50'
              }`}
            >
          <FileKey className="w-5 h-5" />
          Keys
        </button>
        <button
          role="tab"
          aria-selected={activeTab === 'agent'}
          aria-controls="agent-tab-content"
          onClick={() => setActiveTab('agent')}
          className={`flex items-center gap-3 px-6 py-4 text-base font-medium transition-colors ${
            activeTab === 'agent'
              ? 'border-b-[3px] border-purple-active text-purple-active font-semibold'
              : 'border-b-2 border-transparent text-gray-600 dark:text-amber-muted hover:text-gray-900 dark:hover:text-light-neutral hover:bg-gray-50 dark:hover:bg-charcoal-darkest/50'
          }`}
        >
          <Server className="w-5 h-5" />
          Agent
        </button>
      </div>
        </div>
        )}

{!isAdmin && (
        <>
          <CollapsibleSection
            title="Notification Preferences"
            icon={<Bell className="w-5 h-5 text-purple-500" />}
            storageKey="settings_collapsed_notifications"
            defaultExpanded={true}
            summary={getNotificationSummary(notificationPrefs)}
          >
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
                <div>
                  <label htmlFor="unified_timezone" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-2">
                    Timezone
                  </label>
                  <select
                    id="unified_timezone"
                      value={unifiedTimezone || 'UTC'}
                      onChange={(e) => handleUnifiedTimezoneChange(e.target.value)}
                      className="w-full md:w-auto min-w-[200px] px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                    >
                      {timezones.map((tz) => (
                        <option key={tz.value} value={tz.value}>
                          {tz.label}
                        </option>
                      ))}
                    </select>
                    <p className="text-xs text-gray-500 dark:text-amber-muted mt-1">
                      Applies to both Quiet Hours and Daily Digest
                  </p>
                </div>

                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-3">
                      Alert Types
                    </label>
<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {alertTypes.map((type) => (
                  <div key={type.key} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id={`alert-type-${type.key}`}
                      checked={notificationPrefs.alert_types?.[type.key] ?? true}
                      onChange={() => handleToggleAlertType(type.key)}
                      className="w-4 h-4 text-purple-600 border-gray-300 dark:border-gray-border rounded-none focus:ring-purple-500"
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

            <div className="border-t border-gray-200 dark:border-gray-border pt-6">
              <button
                type="button"
                onClick={() => setShowQuietHours(!showQuietHours)}
                aria-expanded={!!showQuietHours}
                aria-controls="quiet-hours-content"
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
<div id="quiet-hours-content" className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="quiet_hours_enabled"
                    checked={notificationPrefs.quiet_hours?.enabled ?? false}
                    onChange={(e) => handleQuietHoursChange('enabled', e.target.checked)}
                    className="w-4 h-4 text-purple-600 border-gray-300 dark:border-gray-border rounded-none focus:ring-purple-500"
                  />
                  <label htmlFor="quiet_hours_enabled" className="text-sm text-gray-700 dark:text-amber-primary">
                    Enable Quiet Hours
                  </label>
                </div>
                <div>
                  <label htmlFor="quiet_hours_start" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                    Start Time
                  </label>
                  <input
                    type="time"
                    id="quiet_hours_start"
                    value={notificationPrefs.quiet_hours?.start_time || '22:00'}
                    onChange={(e) => handleQuietHoursChange('start_time', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                  />
                </div>
                <div>
                  <label htmlFor="quiet_hours_end" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                    End Time
                  </label>
                  <input
                    type="time"
                    id="quiet_hours_end"
                    value={notificationPrefs.quiet_hours?.end_time || '08:00'}
                    onChange={(e) => handleQuietHoursChange('end_time', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                  />
                </div>
              </div>
                    )}
              </div>

              <div className="border-t border-gray-200 dark:border-gray-border pt-6">
                  <button
                    type="button"
                    onClick={() => setShowDigest(!showDigest)}
                    aria-expanded={!!showDigest}
                    aria-controls="daily-digest-content"
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
<div id="daily-digest-content" className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="digest_enabled"
                    checked={notificationPrefs.daily_digest?.enabled ?? false}
                    onChange={(e) => handleDigestChange('enabled', e.target.checked)}
                    className="w-4 h-4 text-purple-600 border-gray-300 dark:border-gray-border rounded-none focus:ring-purple-500"
                  />
                  <label htmlFor="digest_enabled" className="text-sm text-gray-700 dark:text-amber-primary">
                    Enable Daily Digest
                  </label>
                </div>
                <div>
                  <label htmlFor="digest_time" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                    Digest Time
                  </label>
                  <input
                    type="time"
                    id="digest_time"
                    value={notificationPrefs.daily_digest?.time || '09:00'}
                    onChange={(e) => handleDigestChange('time', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                  />
                </div>
              </div>
                    )}
                  </div>
                </div>
              )}
            </CollapsibleSection>

            <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none">
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

        {isAdmin && (
          <>
            {activeTab === 'alerts' && (
              <div id="alerts-tab-content" role="tabpanel" className="space-y-6">
                <div className="flex justify-end mb-4">
<select
                  onChange={handleJumpToSection}
                  className="text-sm px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral focus:outline-none focus:ring-2 focus:ring-purple-active"
                  defaultValue=""
                  aria-label="Jump to section"
                >
<option value="" disabled>Jump to section...</option>
              <option value="email-section">Email Configuration</option>
              <option value="notifications-section">Notifications</option>
              <option value="alert-rules-section">Alert Rules</option>
                </select>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-6">
                  <CollapsibleSection
                id="email-section"
                title="Email Configuration"
                icon={<Mail className="w-5 h-5 text-purple-500" />}
                storageKey="settings_collapsed_email"
                defaultExpanded={false}
                summary={getSMTPSummary(smtpConfig, instanceSettings)}
                expanded={emailExpanded}
                onExpandedChange={setEmailExpanded}
              >
                {smtpLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader className="w-6 h-6 animate-spin text-purple-500" />
                  </div>
                ) : (
                                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                        {/* Row 1: Instance URL | Enable Email toggle */}
                                                        <div>
<label htmlFor="instance_url" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                                        Instance URL
                                        <span className="text-xs text-gray-500 dark:text-amber-muted ml-1">- Used for email links</span>
                                    </label>
                                                                <input
                                                                        type="url"
                                                                        id="instance_url"
                                                                        value={instanceUrl}
                                                                        onChange={(e) => setInstanceUrl(e.target.value)}
                                                                        onBlur={() => updateInstanceMutation.mutate(instanceUrl)}
                                                                        placeholder="https://runic.example.com"
                                                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                                                                />
                                                        </div>
                  <div className="flex flex-col">
                    {/* Ghost label spacer - matches label height */}
                    <div className="text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                      &nbsp;
                    </div>
                    {/* Toggle container - matches input height */}
                    <div className="flex items-center h-[42px]">
                      <div className="flex items-center gap-3">
                        <ToggleSwitch
                          checked={smtpFormData.enabled}
                          onChange={(value) => setSmtpFormData({ ...smtpFormData, enabled: value })}
                          aria-labelledby="enable-email-label"
                        />
                        <label id="enable-email-label" className="text-sm text-gray-700 dark:text-amber-primary">
                          Enable Email
                        </label>
                      </div>
                    </div>
                  </div>

                                                        {/* Row 2: SMTP Host | SMTP Port + Use TLS */}
                                                        <div>
                                                                <label htmlFor="smtp_host" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                                                                        SMTP Host
                                                                </label>
                                                                <input
                                                                        type="text"
                                                                        id="smtp_host"
                                                                        value={smtpFormData.host}
                                                                        onChange={(e) => setSmtpFormData({ ...smtpFormData, host: e.target.value })}
                                                                        placeholder="smtp.example.com"
                                                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                                                                />
                                                        </div>
                                <div className={`flex items-end gap-4 ${portError ? 'mb-6' : ''}`}>
                                    <div className="relative">
                                        <label htmlFor="smtp_port" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                                            SMTP Port
                                        </label>
                                        <input
                                            type="text"
                                            inputMode="numeric"
                                            id="smtp_port"
                                            value={smtpFormData.port}
                                            onChange={handlePortChange}
                                            aria-invalid={!!portError}
                                            aria-describedby={portError ? 'smtp_port_error' : undefined}
                                            className="w-20 px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                                        />
                                        {portError && (
                                            <p id="smtp_port_error" className="absolute text-xs text-red-500 -bottom-5 left-0 whitespace-nowrap">{portError}</p>
                                        )}
                                    </div>
                    {/* Use TLS toggle - aligned with Port input */}
                    <div className="flex flex-col">
                      {/* Ghost label spacer - matches label height */}
                      <div className="text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                        &nbsp;
                      </div>
                      {/* Toggle container - matches input height */}
                      <div className="flex items-center h-[42px]">
                        <div className="flex items-center gap-3">
                          <ToggleSwitch
                            checked={smtpFormData.use_tls}
                            onChange={(value) => setSmtpFormData({ ...smtpFormData, use_tls: value })}
                            aria-labelledby="use-tls-label"
                          />
                          <label id="use-tls-label" className="text-sm text-gray-700 dark:text-amber-primary">
                            Use TLS
                          </label>
                        </div>
                      </div>
                    </div>
                                                        </div>

                                                        {/* Row 3: Username | Password */}
                                                        <div>
                                                                <label htmlFor="smtp_username" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                                                                        Username
                                                                </label>
                                                                <input
                                                                        type="text"
                                                                        id="smtp_username"
                                                                        value={smtpFormData.username}
                                                                        onChange={(e) => setSmtpFormData({ ...smtpFormData, username: e.target.value })}
                                                                        placeholder="username"
                                                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                                                                />
                                                        </div>
                                                        <div>
                                                                <label htmlFor="smtp_password" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                                                                        Password
                                                                </label>
                                                                <div className="relative">
                                                                        <input
                                                                                type={showPassword ? 'text' : 'password'}
                                                                                id="smtp_password"
                                                                                value={smtpFormData.password}
                                                                                onChange={(e) => setSmtpFormData({ ...smtpFormData, password: e.target.value })}
                                                                                placeholder={smtpConfig?.password_set ? '••••••••' : 'Enter password'}
                                                                                className="w-full px-3 py-2 pr-10 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
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

                                                        {/* Row 4: From Address | Empty */}
                                                        <div>
                                                                <label htmlFor="smtp_from_address" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                                                                        From Address
                                                                </label>
                                                                <input
                                                                        type="email"
                                                                        id="smtp_from_address"
                                                                        value={smtpFormData.from_address}
                                                                        onChange={(e) => setSmtpFormData({ ...smtpFormData, from_address: e.target.value })}
                                                                        placeholder="alerts@example.com"
                                                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                                                                />
                                                        </div>
                                                        <div></div>
                                                </div>
                )}

                <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-gray-200 dark:border-gray-border">
                  <button
                    onClick={() => testEmailMutation.mutate()}
                    disabled={testEmailMutation.isPending || !smtpFormData.enabled}
                    className="inline-flex items-center gap-2 px-4 py-2 text-sm border border-gray-300 dark:border-gray-border rounded-none text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {testEmailMutation.isPending ? (
                      <Loader className="w-4 h-4 animate-spin" />
                    ) : (
                      <Send className="w-4 h-4" />
                    )}
                    Test Email
                  </button>
<button
          onClick={() => {
            if (portError) {
              showToast('Please fix validation errors', 'error')
              return
            }
            // Convert port string to number for API
            const payload = {
              ...smtpFormData,
              port: smtpFormData.port === '' ? 587 : parseInt(smtpFormData.port, 10),
            }
            updateSmtpMutation.mutate(payload)
          }}
                  disabled={updateSmtpMutation.isPending}
                  className="inline-flex items-center gap-2 px-4 py-2 text-sm bg-purple-active hover:bg-purple-600 text-white rounded-none disabled:opacity-50 border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all"
                >
                  {updateSmtpMutation.isPending ? 'Saving...' : 'Save Email Settings'}
                </button>
                </div>
                </CollapsibleSection>
              </div>

              <div className="space-y-6">
                <CollapsibleSection
id="notifications-section"
            title="Your Notification Preferences"
            icon={<Bell className="w-5 h-5 text-purple-500" />}
            storageKey="settings_collapsed_notifications_admin"
            defaultExpanded={false}
            summary={getNotificationSummary(notificationPrefs)}
            expanded={notificationsExpanded}
            onExpandedChange={setNotificationsExpanded}
          >
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
                <div>
                  <label htmlFor="admin-unified_timezone" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-2">
                    Timezone
                  </label>
                  <select
                    id="admin-unified_timezone"
                        value={unifiedTimezone || 'UTC'}
                        onChange={(e) => handleUnifiedTimezoneChange(e.target.value)}
                        className="w-full md:w-auto min-w-[200px] px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                      >
                        {timezones.map((tz) => (
                          <option key={tz.value} value={tz.value}>
                            {tz.label}
                          </option>
                        ))}
                      </select>
                      <p className="text-xs text-gray-500 dark:text-amber-muted mt-1">
                        Applies to both Quiet Hours and Daily Digest
                      </p>
                  </div>

                  <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-3">
                        Alert Types
                      </label>
<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {alertTypes.map((type) => (
                  <div key={type.key} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id={`admin-alert-type-${type.key}`}
                      checked={notificationPrefs.alert_types?.[type.key] ?? true}
                      onChange={() => handleToggleAlertType(type.key)}
                      className="w-4 h-4 text-purple-600 border-gray-300 dark:border-gray-border rounded-none focus:ring-purple-500"
                    />
                    <label
                      htmlFor={`admin-alert-type-${type.key}`}
                      className="text-sm text-gray-700 dark:text-amber-primary cursor-pointer"
                    >
                      {type.label}
                    </label>
                  </div>
                ))}
              </div>
            </div>

            <div className="border-t border-gray-200 dark:border-gray-border pt-6">
              <button
                type="button"
                onClick={() => setShowQuietHours(!showQuietHours)}
                aria-expanded={!!showQuietHours}
                aria-controls="admin-quiet-hours-content"
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
<div id="admin-quiet-hours-content" className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="admin-quiet_hours_enabled"
                    checked={notificationPrefs.quiet_hours?.enabled ?? false}
                    onChange={(e) => handleQuietHoursChange('enabled', e.target.checked)}
                    className="w-4 h-4 text-purple-600 border-gray-300 dark:border-gray-border rounded-none focus:ring-purple-500"
                  />
                  <label htmlFor="admin-quiet_hours_enabled" className="text-sm text-gray-700 dark:text-amber-primary">
                    Enable Quiet Hours
                  </label>
                </div>
                <div>
                  <label htmlFor="admin-quiet_hours_start" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                    Start Time
                  </label>
                  <input
                    type="time"
                    id="admin-quiet_hours_start"
                    value={notificationPrefs.quiet_hours?.start_time || '22:00'}
                    onChange={(e) => handleQuietHoursChange('start_time', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                  />
                </div>
                <div>
                  <label htmlFor="admin-quiet_hours_end" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                    End Time
                  </label>
                  <input
                    type="time"
                    id="admin-quiet_hours_end"
                    value={notificationPrefs.quiet_hours?.end_time || '08:00'}
                    onChange={(e) => handleQuietHoursChange('end_time', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                  />
                </div>
              </div>
                      )}
                </div>

                <div className="border-t border-gray-200 dark:border-gray-border pt-6">
                  <button
                    type="button"
                    onClick={() => setShowDigest(!showDigest)}
                    aria-expanded={!!showDigest}
                    aria-controls="admin-daily-digest-content"
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
<div id="admin-daily-digest-content" className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="admin-digest_enabled"
                    checked={notificationPrefs.daily_digest?.enabled ?? false}
                    onChange={(e) => handleDigestChange('enabled', e.target.checked)}
                    className="w-4 h-4 text-purple-600 border-gray-300 dark:border-gray-border rounded-none focus:ring-purple-500"
                  />
                  <label htmlFor="admin-digest_enabled" className="text-sm text-gray-700 dark:text-amber-primary">
                    Enable Daily Digest
                  </label>
                </div>
                <div>
                  <label htmlFor="admin-digest_time" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                    Digest Time
                  </label>
                  <input
                    type="time"
                    id="admin-digest_time"
                    value={notificationPrefs.daily_digest?.time || '09:00'}
                    onChange={(e) => handleDigestChange('time', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                  />
                </div>
              </div>
                      )}
                    </div>
                  </div>
                )}
              </CollapsibleSection>
                </div>
              </div>

              <CollapsibleSection
            id="alert-rules-section"
            title="Alert Rules"
            icon={<Bell className="w-5 h-5 text-purple-500" />}
            storageKey="settings_collapsed_alert_rules"
            defaultExpanded={false}
            summary={getAlertRulesSummary(alertRules)}
            expanded={alertRulesExpanded}
            onExpandedChange={setAlertRulesExpanded}
          >
            <AlertSettings showHeader={false} />
          </CollapsibleSection>
        </div>
      )}

            {activeTab === 'logs' && (
              <div id="logs-tab-content" role="tabpanel" className="space-y-6">
                <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none">
                <div className="p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <Database className="w-5 h-5 text-purple-500" />
                      <h2 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">Log Management</h2>
                    </div>
                    <button
                      onClick={() => setShowClearLogsModal(true)}
                      className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded-none"
                    >
                      <Trash2 className="w-4 h-4" />
                  Clear All Logs
                </button>
              </div>
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
            {logSettings?.logs_db_path && (
<div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                  Logs Database Path
                </label>
                <div className="p-2 bg-gray-100 dark:bg-charcoal-darkest rounded-none font-mono text-sm text-gray-700 dark:text-amber-muted">
                        {logSettings.logs_db_path}
                      </div>
              </div>
            )}
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
                        className="px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
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
                          className="w-24 px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
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
            <div id="keys-tab-content" role="tabpanel" className="space-y-6">
              <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none">
                <div className="p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <Shield className="w-5 h-5 text-blue-500" />
                      <h2 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">JWT Secret</h2>
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => setShowDeleteModal('jwt-secret')}
                        className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded-none"
                      >
                        <Trash2 className="w-4 h-4" />
                        Delete
                      </button>
                      <button
                        onClick={() => setShowCreateModal('jwt-secret')}
                        className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-purple-active hover:bg-purple-600 text-white rounded-none border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all"
                      >
                        <Plus className="w-4 h-4" />
                        Create New
                      </button>
                    </div>
                  </div>
                  <p className="text-gray-600 dark:text-amber-muted text-sm">
                    JWT Secret is used for user authentication tokens. Changing this will log out all users.
                  </p>
<div className="mt-4 p-3 bg-gray-100 dark:bg-charcoal-darkest rounded-none font-mono text-sm text-gray-700 dark:text-amber-primary">
              {isLoading ? 'Loading...' : getKeyData('jwt-secret')?.exists ? '•••••••••••••••••••••••••••••••••••••••••' : 'No key configured'}
                  </div>
              </div>
            </div>

            <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none">
                <div className="p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <Key className="w-5 h-5 text-green-500" />
                      <h2 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">Agent JWT Secret</h2>
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => setShowDeleteModal('agent-jwt-secret')}
                        className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded-none"
                      >
                        <Trash2 className="w-4 h-4" />
                        Delete
                      </button>
                      <button
                        onClick={() => setShowCreateModal('agent-jwt-secret')}
                        className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-purple-active hover:bg-purple-600 text-white rounded-none border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all"
                      >
                        <Plus className="w-4 h-4" />
                        Create New
                      </button>
                    </div>
                  </div>
                  <p className="text-gray-600 dark:text-amber-muted text-sm">
                    Agent JWT Secret is used to authenticate agents with the control plane. Changing this will disconnect all agents.
                  </p>
<div className="mt-4 p-3 bg-gray-100 dark:bg-charcoal-darkest rounded-none font-mono text-sm text-gray-700 dark:text-amber-primary">
              {isLoading ? 'Loading...' : getKeyData('agent-jwt-secret')?.exists ? '•••••••••••••••••••••••••••••••••••••••••' : 'No key configured'}
                  </div>
        </div>
      </div>
      </div>
      )}

      {activeTab === 'agent' && (
        <div id="agent-tab-content" role="tabpanel" className="space-y-6">
          <CollapsibleSection
            title="Agent Version"
            icon={<Server className="w-5 h-5 text-purple-500" />}
            storageKey="settings_collapsed_agent_version"
            defaultExpanded={true}
          >
            <div className="space-y-4">
              <p className="text-sm text-gray-600 dark:text-amber-muted">
                Set the latest agent version. Agents running an older version will show an update indicator in the Peers page. Leave blank to use the server version as the latest.
              </p>
              <div>
                <label htmlFor="latest_agent_version" className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                  Latest Agent Version
                </label>
                <input
                  type="text"
                  id="latest_agent_version"
                  value={latestAgentVersion}
                  onChange={(e) => {
                    setLatestAgentVersion(e.target.value)
                    setAgentVersionIsDefault(false)
                  }}
                  placeholder="e.g., 1.2.3"
                  className="w-full md:w-64 px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
                />
                {agentVersionIsDefault && (
                  <p className="text-xs text-gray-500 dark:text-amber-muted mt-1">
                    Currently using server version as default
                  </p>
                )}
              </div>
              <div className="flex justify-end">
                <button
                  onClick={() => updateAgentVersionMutation.mutate(latestAgentVersion)}
                  disabled={updateAgentVersionMutation.isPending}
                  className="inline-flex items-center gap-2 px-4 py-2 text-sm bg-purple-active hover:bg-purple-600 text-white rounded-none disabled:opacity-50 border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all"
                >
                  {updateAgentVersionMutation.isPending ? 'Saving...' : 'Save'}
                </button>
              </div>
            </div>
          </CollapsibleSection>
        </div>
      )}

      {showDeleteModal && (
            <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
              <div ref={deleteModalRef} className="bg-white dark:bg-charcoal-dark rounded-none p-6 max-w-md w-full mx-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                  Delete {showDeleteModal === 'jwt-secret' ? 'JWT Secret' : 'Agent JWT Secret'}?
                </h3>
                <p className="text-gray-600 dark:text-amber-muted mb-6">
                  This action cannot be undone and will {showDeleteModal === 'jwt-secret' ? 'log out all users' : 'disconnect all agents'}.
                </p>
                <div className="flex gap-3">
                  <button
                    onClick={() => setShowDeleteModal(null)}
                    className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border rounded-none text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => handleDelete(showDeleteModal)}
                    disabled={deleteMutation.isPending}
                    className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-none disabled:opacity-50"
                  >
                    {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {showCreateModal && (
            <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
              <div ref={createModalRef} className="bg-white dark:bg-charcoal-dark rounded-none p-6 max-w-md w-full mx-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                  Create New {showCreateModal === 'jwt-secret' ? 'JWT Secret' : 'Agent JWT Secret'}?
                </h3>
                <p className="text-gray-600 dark:text-amber-muted mb-6">
                  This will generate a new key. {showCreateModal === 'jwt-secret' ? 'All users will be logged out.' : 'All agents will be disconnected.'}
                </p>
                <div className="flex gap-3">
                  <button
                    onClick={() => setShowCreateModal(null)}
                    className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border rounded-none text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => handleCreate(showCreateModal)}
                    disabled={createMutation.isPending}
                    className="flex-1 px-4 py-2 bg-purple-active hover:bg-purple-600 text-white rounded-none disabled:opacity-50 border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all"
                  >
                    {createMutation.isPending ? 'Creating...' : 'Create'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {showClearLogsModal && (
            <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
              <div className="bg-white dark:bg-charcoal-dark rounded-none p-6 max-w-md w-full mx-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                  Clear All Logs?
                </h3>
                <p className="text-gray-600 dark:text-amber-muted mb-6">
                  This will permanently delete all {logSettings?.log_count?.toLocaleString() || 0} firewall logs. This action cannot be undone.
                </p>
                <div className="flex gap-3">
                  <button
                    onClick={() => setShowClearLogsModal(false)}
                    className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border rounded-none text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => clearLogsMutation.mutate()}
                    disabled={clearLogsMutation.isPending}
                    className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-none disabled:opacity-50"
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
