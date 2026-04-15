/**
 * Settings summary utility functions
 * Generates concise badge text for collapsed settings sections
 */

/**
 * Get SMTP configuration summary
 * @param {Object} smtpConfig - SMTP configuration object
 * @param {string} smtpConfig.host - SMTP server host
 * @param {number} smtpConfig.port - SMTP server port
 * @param {string} smtpConfig.username - SMTP username
 * @param {string} smtpConfig.from_address - From email address
 * @param {boolean} smtpConfig.enabled - Whether SMTP is enabled
 * @returns {string} "SMTP: configured" | "SMTP: not configured"
 */
export function getSMTPSummary(smtpConfig) {
  if (!smtpConfig) {
    return 'SMTP: not configured'
  }
  // Consider configured if host is set (minimum required field)
  const isConfigured = smtpConfig.host && smtpConfig.host.trim() !== ''
  return isConfigured ? 'SMTP: configured' : 'SMTP: not configured'
}

/**
 * Get instance settings summary
 * @param {Object} instanceSettings - Instance settings object
 * @param {string} instanceSettings.url - Instance URL
 * @returns {string} "Instance: set" | "Instance: not set"
 */
export function getInstanceSummary(instanceSettings) {
  if (!instanceSettings) {
    return 'Instance: not set'
  }
  // Consider set if URL is configured
  const isSet = instanceSettings.url && instanceSettings.url.trim() !== ''
  return isSet ? 'Instance: set' : 'Instance: not set'
}

/**
 * Get notification preferences summary
 * @param {Object} notificationPrefs - Notification preferences object
 * @param {Object} notificationPrefs.alert_types - Alert type toggles (key: boolean)
 * @param {Object} notificationPrefs.quiet_hours - Quiet hours settings
 * @param {string} notificationPrefs.quiet_hours.timezone - Timezone setting
 * @returns {string} "TZ: UTC | 5 alerts enabled"
 */
export function getNotificationSummary(notificationPrefs) {
  if (!notificationPrefs) {
    return 'TZ: UTC | 0 alerts enabled'
  }

  // Get timezone from quiet_hours, default to UTC
  const timezone = notificationPrefs.quiet_hours?.timezone || 'UTC'

  // Count enabled alert types
  const alertTypes = notificationPrefs.alert_types || {}
  const enabledCount = Object.values(alertTypes).filter(Boolean).length

  return `TZ: ${timezone} | ${enabledCount} alerts enabled`
}

/**
 * Get alert rules summary
 * @param {Array} alertRules - Array of alert rule objects
 * @param {boolean} alertRules[].enabled - Whether the rule is enabled
 * @returns {string} "3/6 rules enabled"
 */
export function getAlertRulesSummary(alertRules) {
  const TOTAL_RULES = 6

  if (!alertRules || !Array.isArray(alertRules)) {
    return `0/${TOTAL_RULES} rules enabled`
  }

  const enabledCount = alertRules.filter(rule => rule?.enabled).length
  return `${enabledCount}/${TOTAL_RULES} rules enabled`
}
