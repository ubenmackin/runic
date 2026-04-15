import {
getSMTPSummary,
getNotificationSummary,
getAlertRulesSummary,
} from './settingsSummary'
import { describe, test, expect } from 'vitest'

describe('settingsSummary', () => {
describe('getSMTPSummary', () => {
describe('with SMTP only (no instance settings)', () => {
test('returns "SMTP: configured" when host is set', () => {
const smtpConfig = {
host: 'smtp.example.com',
port: 587,
username: 'alerts',
from_address: 'alerts@example.com',
enabled: true,
}

expect(getSMTPSummary(smtpConfig)).toBe('SMTP: configured')
})

test('returns "SMTP: configured" when only host is provided', () => {
const smtpConfig = {
host: 'smtp.example.com',
}

expect(getSMTPSummary(smtpConfig)).toBe('SMTP: configured')
})

test('returns "SMTP: not configured" when host is empty string', () => {
const smtpConfig = {
host: '',
port: 587,
username: 'alerts',
}

expect(getSMTPSummary(smtpConfig)).toBe('SMTP: not configured')
})

test('returns "SMTP: not configured" when host is whitespace only', () => {
const smtpConfig = {
host: ' ',
port: 587,
}

expect(getSMTPSummary(smtpConfig)).toBe('SMTP: not configured')
})

test('returns "SMTP: not configured" for null input', () => {
expect(getSMTPSummary(null)).toBe('SMTP: not configured')
})

test('returns "SMTP: not configured" for undefined input', () => {
expect(getSMTPSummary(undefined)).toBe('SMTP: not configured')
})

test('returns "SMTP: not configured" for empty object', () => {
expect(getSMTPSummary({})).toBe('SMTP: not configured')
})

test('ignores other fields when determining configuration status', () => {
// Even with port, username, etc., only host matters
const smtpConfig = {
port: 587,
username: 'user',
password: 'pass',
from_address: 'test@example.com',
enabled: true,
// host is missing
}

expect(getSMTPSummary(smtpConfig)).toBe('SMTP: not configured')
})
})

describe('with both SMTP and instance settings', () => {
test('returns combined status when both are configured', () => {
const smtpConfig = { host: 'smtp.example.com' }
const instanceSettings = { url: 'https://runic.example.com' }

expect(getSMTPSummary(smtpConfig, instanceSettings)).toBe('SMTP: configured | Instance: set')
})

test('returns combined status when SMTP configured but instance not set', () => {
const smtpConfig = { host: 'smtp.example.com' }
const instanceSettings = { url: '' }

expect(getSMTPSummary(smtpConfig, instanceSettings)).toBe('SMTP: configured')
})

test('returns combined status when SMTP not configured but instance is set', () => {
const smtpConfig = { host: '' }
const instanceSettings = { url: 'https://runic.example.com' }

expect(getSMTPSummary(smtpConfig, instanceSettings)).toBe('SMTP: not configured | Instance: set')
})

test('returns SMTP status only when instance settings is null', () => {
const smtpConfig = { host: 'smtp.example.com' }

expect(getSMTPSummary(smtpConfig, null)).toBe('SMTP: configured')
})

test('returns SMTP status only when instance settings is undefined', () => {
const smtpConfig = { host: 'smtp.example.com' }

expect(getSMTPSummary(smtpConfig, undefined)).toBe('SMTP: configured')
})

test('returns SMTP status only when instance settings is empty object', () => {
const smtpConfig = { host: 'smtp.example.com' }
const instanceSettings = {}

expect(getSMTPSummary(smtpConfig, instanceSettings)).toBe('SMTP: configured')
})

test('handles both null inputs', () => {
expect(getSMTPSummary(null, null)).toBe('SMTP: not configured')
})

test('handles whitespace URL in instance settings', () => {
const smtpConfig = { host: 'smtp.example.com' }
const instanceSettings = { url: '   ' }

expect(getSMTPSummary(smtpConfig, instanceSettings)).toBe('SMTP: configured')
})
})
})
})

describe('getNotificationSummary', () => {
    test('returns correct summary with timezone and alert count', () => {
      const notificationPrefs = {
        alert_types: {
          bundle_deployed: true,
          bundle_failed: true,
          peer_offline: false,
          peer_online: false,
          blocked_spike: true,
          new_peer: false,
        },
        quiet_hours: {
          timezone: 'America/New_York',
          enabled: true,
          start_time: '22:00',
          end_time: '08:00',
        },
      }

      expect(getNotificationSummary(notificationPrefs)).toBe('TZ: America/New_York | 3 alerts enabled')
    })

    test('counts enabled alerts correctly', () => {
      const notificationPrefs = {
        alert_types: {
          bundle_deployed: true,
          bundle_failed: true,
          peer_offline: true,
          peer_online: true,
          blocked_spike: true,
          new_peer: true,
        },
        quiet_hours: {
          timezone: 'UTC',
        },
      }

      expect(getNotificationSummary(notificationPrefs)).toBe('TZ: UTC | 6 alerts enabled')
    })

    test('returns "0 alerts enabled" when all alerts are disabled', () => {
      const notificationPrefs = {
        alert_types: {
          bundle_deployed: false,
          bundle_failed: false,
          peer_offline: false,
          peer_online: false,
          blocked_spike: false,
          new_peer: false,
        },
        quiet_hours: {
          timezone: 'Europe/London',
        },
      }

      expect(getNotificationSummary(notificationPrefs)).toBe('TZ: Europe/London | 0 alerts enabled')
    })

    test('defaults to UTC timezone when quiet_hours.timezone is missing', () => {
      const notificationPrefs = {
        alert_types: {
          bundle_deployed: true,
        },
        quiet_hours: {
          // timezone not set
        },
      }

      expect(getNotificationSummary(notificationPrefs)).toBe('TZ: UTC | 1 alerts enabled')
    })

    test('defaults to UTC timezone when quiet_hours is missing', () => {
      const notificationPrefs = {
        alert_types: {
          bundle_deployed: true,
          peer_offline: true,
        },
        // quiet_hours missing entirely
      }

      expect(getNotificationSummary(notificationPrefs)).toBe('TZ: UTC | 2 alerts enabled')
    })

    test('handles missing alert_types with default to empty object', () => {
      const notificationPrefs = {
        quiet_hours: {
          timezone: 'Asia/Tokyo',
        },
      }

      expect(getNotificationSummary(notificationPrefs)).toBe('TZ: Asia/Tokyo | 0 alerts enabled')
    })

    test('returns default for null input', () => {
      expect(getNotificationSummary(null)).toBe('TZ: UTC | 0 alerts enabled')
    })

    test('returns default for undefined input', () => {
      expect(getNotificationSummary(undefined)).toBe('TZ: UTC | 0 alerts enabled')
    })

    test('handles empty object input', () => {
      expect(getNotificationSummary({})).toBe('TZ: UTC | 0 alerts enabled')
    })

    test('handles various timezone formats', () => {
      const notificationPrefs = {
        alert_types: { bundle_deployed: true },
        quiet_hours: { timezone: 'America/Los_Angeles' },
      }

      expect(getNotificationSummary(notificationPrefs)).toBe('TZ: America/Los_Angeles | 1 alerts enabled')
    })
  })

  describe('getAlertRulesSummary', () => {
    test('returns correct summary for partially enabled rules', () => {
      const alertRules = [
        { enabled: true },
        { enabled: true },
        { enabled: false },
        { enabled: true },
        { enabled: false },
        { enabled: false },
      ]

      expect(getAlertRulesSummary(alertRules)).toBe('3/6 rules enabled')
    })

    test('returns correct summary when all rules are enabled', () => {
      const alertRules = [
        { enabled: true },
        { enabled: true },
        { enabled: true },
        { enabled: true },
        { enabled: true },
        { enabled: true },
      ]

      expect(getAlertRulesSummary(alertRules)).toBe('6/6 rules enabled')
    })

    test('returns correct summary when all rules are disabled', () => {
      const alertRules = [
        { enabled: false },
        { enabled: false },
        { enabled: false },
        { enabled: false },
        { enabled: false },
        { enabled: false },
      ]

      expect(getAlertRulesSummary(alertRules)).toBe('0/6 rules enabled')
    })

    test('returns default for null input', () => {
      expect(getAlertRulesSummary(null)).toBe('0/6 rules enabled')
    })

    test('returns default for undefined input', () => {
      expect(getAlertRulesSummary(undefined)).toBe('0/6 rules enabled')
    })

    test('returns default for non-array input', () => {
      expect(getAlertRulesSummary({})).toBe('0/6 rules enabled')
      expect(getAlertRulesSummary('not an array')).toBe('0/6 rules enabled')
      expect(getAlertRulesSummary(123)).toBe('0/6 rules enabled')
    })

    test('handles empty array', () => {
      expect(getAlertRulesSummary([])).toBe('0/6 rules enabled')
    })

    test('handles array with fewer than 6 rules', () => {
      const alertRules = [
        { enabled: true },
        { enabled: false },
      ]

      expect(getAlertRulesSummary(alertRules)).toBe('1/6 rules enabled')
    })

    test('handles array with more than 6 rules', () => {
      const alertRules = [
        { enabled: true },
        { enabled: true },
        { enabled: true },
        { enabled: true },
        { enabled: true },
        { enabled: true },
        { enabled: true }, // Extra rule
      ]

      expect(getAlertRulesSummary(alertRules)).toBe('7/6 rules enabled')
    })

    test('handles rules with missing enabled property', () => {
      const alertRules = [
        { enabled: true },
        { }, // Missing enabled property
        { enabled: false },
        null, // Null rule
        { enabled: true },
        undefined, // Undefined rule
      ]

      // Only rules with enabled: true count
      expect(getAlertRulesSummary(alertRules)).toBe('2/6 rules enabled')
    })

    test('uses optional chaining to handle malformed rules', () => {
      const alertRules = [
        { enabled: true },
        null,
        { enabled: false },
        { enabled: true },
        undefined,
        { enabled: true },
      ]

      expect(getAlertRulesSummary(alertRules)).toBe('3/6 rules enabled')
})
})
