/**
* Get Email Configuration summary (combines SMTP and Instance URL status)
* @param {Object} smtpConfig - SMTP configuration object
* @param {string} smtpConfig.host - SMTP server host
* @param {number} smtpConfig.port - SMTP server port
* @param {string} smtpConfig.username - SMTP username
* @param {string} smtpConfig.from_address - From email address
* @param {boolean} smtpConfig.enabled - Whether SMTP is enabled
* @param {Object} instanceSettings - Instance settings object (optional)
* @param {string} instanceSettings.url - Instance URL
* @returns {string} Summary string like "SMTP: configured | Instance: set" or "SMTP: not configured"
*/
export function getSMTPSummary(smtpConfig, instanceSettings) {
  const smtpConfigured = smtpConfig?.host && smtpConfig.host.trim() !== ''
  const smtpStatus = smtpConfigured ? 'SMTP: configured' : 'SMTP: not configured'

  const instanceSet = instanceSettings?.url && instanceSettings.url.trim() !== ''

  if (instanceSet) {
    return `${smtpStatus} | Instance: set`
  }

  return smtpStatus
}

/**
 * Get notification preferences summary
 * @param {Object} notificationPrefs - Notification preferences object
 * @param {Object} notificationPrefs.quiet_hours - Quiet hours settings
 * @param {string} notificationPrefs.quiet_hours.timezone - Timezone setting
 * @returns {string} "TZ: UTC"
 */
export function getNotificationSummary(notificationPrefs) {
  if (!notificationPrefs) {
    return 'TZ: UTC'
  }
  const timezone = notificationPrefs.quiet_hours?.timezone || 'UTC'
  return `TZ: ${timezone}`
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
