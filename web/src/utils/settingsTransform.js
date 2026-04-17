/**
* Settings data transformation utilities
* Handles conversion between frontend nested structures and backend flat fields
*/

/**
* Get the browser's detected timezone using Intl API
* @returns {string} IANA timezone string (e.g., 'America/New_York', 'UTC')
*/
export function getBrowserTimezone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    return 'UTC'
  }
}

/**
* Alert types supported by the notification system
*/
export const alertTypes = [
  { key: 'bundle_deployed', label: 'Bundle Deployed' },
  { key: 'bundle_failed', label: 'Bundle Failed' },
  { key: 'peer_offline', label: 'Peer Offline' },
  { key: 'peer_online', label: 'Peer Online' },
  { key: 'blocked_spike', label: 'Blocked Spike' },
  { key: 'new_peer', label: 'New Peer' },
]

/**
 * Transform notification preferences from backend flat structure to frontend nested structure
 * @param {Object} backendPrefs - Backend notification preferences with flat fields
 * @returns {Object} Frontend notification preferences with nested structure
 */
export function transformPrefsFromBackend(backendPrefs) {
  if (!backendPrefs) {
    return null
  }

  // Wrap in try-catch to handle malformed JSON gracefully
  let enabledAlerts = []
  try {
    enabledAlerts = backendPrefs.enabled_alerts ? JSON.parse(backendPrefs.enabled_alerts) : []
  } catch {
    enabledAlerts = []
  }
  const alertTypesObj = {}
  alertTypes.forEach(type => {
    // If no alerts are explicitly enabled, default all to true
    alertTypesObj[type.key] = enabledAlerts.length === 0 || enabledAlerts.includes(type.key)
  })

  // Handle unified timezone: prefer quiet_hours_timezone, fall back to digest_timezone,
  // then to browser-detected timezone if both are empty
  const quietHoursTimezone = backendPrefs.quiet_hours_timezone
  const digestTimezone = backendPrefs.digest_timezone

  let unifiedTimezone
  if (quietHoursTimezone && digestTimezone && quietHoursTimezone !== digestTimezone) {
    // If both exist and differ, prefer quiet_hours_timezone for consistency
    unifiedTimezone = quietHoursTimezone
  } else if (quietHoursTimezone) {
    unifiedTimezone = quietHoursTimezone
  } else if (digestTimezone) {
    unifiedTimezone = digestTimezone
  } else {
    unifiedTimezone = getBrowserTimezone()
  }

  return {
    alert_types: alertTypesObj,
    quiet_hours: {
      enabled: backendPrefs.quiet_hours_enabled ?? false,
      start_time: backendPrefs.quiet_hours_start || '22:00',
      end_time: backendPrefs.quiet_hours_end || '08:00',
      timezone: unifiedTimezone,
    },
    daily_digest: {
      enabled: backendPrefs.digest_enabled ?? false,
      time: backendPrefs.digest_time || '09:00',
    },
  }
}

/**
 * Transform notification preferences from frontend nested structure to backend flat structure
 * @param {Object} prefs - Frontend notification preferences with nested structure
 * @returns {Object} Backend notification preferences with flat fields
 */
export function transformPrefsToBackend(prefs) {
  const unifiedTimezone = prefs.quiet_hours?.timezone || getBrowserTimezone()

  return {
    enabled_alerts: JSON.stringify(
      Object.entries(prefs.alert_types || {})
        .filter(([_key, val]) => val)
        .map(([key]) => key)
    ),
    quiet_hours_enabled: prefs.quiet_hours?.enabled ?? false,
    quiet_hours_start: prefs.quiet_hours?.start_time || '22:00',
    quiet_hours_end: prefs.quiet_hours?.end_time || '08:00',
    quiet_hours_timezone: unifiedTimezone,
    digest_enabled: prefs.daily_digest?.enabled ?? false,
    digest_frequency: 'daily',
    digest_time: prefs.daily_digest?.time || '09:00',
    // Sync timezone to digest_timezone for backward compatibility
    digest_timezone: unifiedTimezone,
  }
}

/**
 * Transform SMTP configuration from backend to frontend form state
 * @param {Object} smtpConfig - Backend SMTP configuration
 * @returns {Object} SMTP form data for frontend
 */
export function transformSMTPFromBackend(smtpConfig) {
  if (!smtpConfig) {
    return {
      host: '',
      port: '587',
      username: '',
      password: '',
      use_tls: true,
      from_address: '',
      enabled: false,
    }
  }

  return {
    host: smtpConfig.host || '',
    port: smtpConfig.port ? String(smtpConfig.port) : '587',
    username: smtpConfig.username || '',
    password: '', // Never populate password from fetched config
    use_tls: smtpConfig.use_tls ?? true,
    from_address: smtpConfig.from_address || '',
    enabled: smtpConfig.enabled ?? false,
  }
}
