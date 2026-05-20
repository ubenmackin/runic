import { Loader } from 'lucide-react'

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

export default function NotificationPrefsForm({
  prefs,
  unifiedTimezone,
  loading,
  error,
  showQuietHours,
  setShowQuietHours,
  showDigest,
  setShowDigest,
  onQuietHoursChange,
  onDigestChange,
  onUnifiedTimezoneChange,
  idPrefix = '',
}) {
  const tzId = idPrefix ? `${idPrefix}-unified_timezone` : 'unified_timezone'
  const quietHoursEnabledId = idPrefix ? `${idPrefix}-quiet_hours_enabled` : 'quiet_hours_enabled'
  const quietHoursStartId = idPrefix ? `${idPrefix}-quiet_hours_start` : 'quiet_hours_start'
  const quietHoursEndId = idPrefix ? `${idPrefix}-quiet_hours_end` : 'quiet_hours_end'
  const quietHoursContentId = idPrefix ? `${idPrefix}-quiet-hours-content` : 'quiet-hours-content'
  const digestEnabledId = idPrefix ? `${idPrefix}-digest_enabled` : 'digest_enabled'
  const digestTimeId = idPrefix ? `${idPrefix}-digest_time` : 'digest_time'
  const digestContentId = idPrefix ? `${idPrefix}-daily-digest-content` : 'daily-digest-content'

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader className="w-6 h-6 animate-spin text-purple-500" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center py-8">
        <p className="text-gray-600 dark:text-amber-muted">
          Please log in to configure notification preferences.
        </p>
      </div>
    )
  }

  if (!prefs) return null

  return (
    <div className="space-y-6">
      <div>
        <label htmlFor={tzId} className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-2">
          Timezone
        </label>
        <select
          id={tzId}
          value={unifiedTimezone || 'UTC'}
          onChange={(e) => onUnifiedTimezoneChange(e.target.value)}
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

      <div className="border-t border-gray-200 dark:border-gray-border pt-6">
        <button
          type="button"
          onClick={() => setShowQuietHours(!showQuietHours)}
          aria-expanded={!!showQuietHours}
          aria-controls={quietHoursContentId}
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
          <div id={quietHoursContentId} className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id={quietHoursEnabledId}
                checked={prefs.quiet_hours?.enabled ?? false}
                onChange={(e) => onQuietHoursChange('enabled', e.target.checked)}
                className="w-4 h-4 text-purple-600 border-gray-300 dark:border-gray-border rounded-none focus:ring-purple-500"
              />
              <label htmlFor={quietHoursEnabledId} className="text-sm text-gray-700 dark:text-amber-primary">
                Enable Quiet Hours
              </label>
            </div>
            <div>
              <label htmlFor={quietHoursStartId} className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                Start Time
              </label>
              <input
                type="time"
                id={quietHoursStartId}
                value={prefs.quiet_hours?.start_time || '22:00'}
                onChange={(e) => onQuietHoursChange('start_time', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
              />
            </div>
            <div>
              <label htmlFor={quietHoursEndId} className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                End Time
              </label>
              <input
                type="time"
                id={quietHoursEndId}
                value={prefs.quiet_hours?.end_time || '08:00'}
                onChange={(e) => onQuietHoursChange('end_time', e.target.value)}
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
          aria-controls={digestContentId}
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
          <div id={digestContentId} className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id={digestEnabledId}
                checked={prefs.daily_digest?.enabled ?? false}
                onChange={(e) => onDigestChange('enabled', e.target.checked)}
                className="w-4 h-4 text-purple-600 border-gray-300 dark:border-gray-border rounded-none focus:ring-purple-500"
              />
              <label htmlFor={digestEnabledId} className="text-sm text-gray-700 dark:text-amber-primary">
                Enable Daily Digest
              </label>
            </div>
            <div>
              <label htmlFor={digestTimeId} className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                Digest Time
              </label>
              <input
                type="time"
                id={digestTimeId}
                value={prefs.daily_digest?.time || '09:00'}
                onChange={(e) => onDigestChange('time', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
              />
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
