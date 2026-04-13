import {
  transformPrefsFromBackend,
  transformPrefsToBackend,
  transformSMTPFromBackend,
  alertTypes,
} from './settingsTransform'
import { describe, test, expect } from 'vitest'

describe('settingsTransform', () => {
  describe('transformPrefsFromBackend (backend to frontend)', () => {
    test('transforms flat backend structure to nested frontend structure', () => {
      const backendPrefs = {
        enabled_alerts: '["bundle_deployed", "peer_offline"]',
        quiet_hours_enabled: true,
        quiet_hours_start: '22:00',
        quiet_hours_end: '08:00',
        quiet_hours_timezone: 'America/New_York',
        digest_enabled: true,
        digest_time: '09:30',
      }

      const result = transformPrefsFromBackend(backendPrefs)

      // Verify alert_types is an object with correct values
      expect(result.alert_types).toEqual({
        bundle_deployed: true,
        bundle_failed: false,
        peer_offline: true,
        peer_online: false,
        blocked_spike: false,
        new_peer: false,
      })

      // Verify quiet_hours nested structure
      expect(result.quiet_hours).toEqual({
        enabled: true,
        start_time: '22:00',
        end_time: '08:00',
        timezone: 'America/New_York',
      })

      // Verify daily_digest nested structure
      expect(result.daily_digest).toEqual({
        enabled: true,
        time: '09:30',
      })
    })

    test('handles null/undefined input', () => {
      expect(transformPrefsFromBackend(null)).toBe(null)
      expect(transformPrefsFromBackend(undefined)).toBe(null)
    })

    test('defaults all alert types to true when enabled_alerts is empty', () => {
      const backendPrefs = {
        enabled_alerts: '[]',
      }

      const result = transformPrefsFromBackend(backendPrefs)

    alertTypes.forEach(type => {
      expect(result.alert_types[type.key]).toBe(true)
    })
  })

  test('uses default values for missing fields', () => {
      const backendPrefs = {
        enabled_alerts: '["bundle_deployed"]',
      }

      const result = transformPrefsFromBackend(backendPrefs)

      expect(result.quiet_hours).toEqual({
        enabled: false,
        start_time: '22:00',
        end_time: '08:00',
        timezone: 'UTC',
      })

      expect(result.daily_digest).toEqual({
        enabled: false,
        time: '09:00',
      })
    })

    test('parses enabled_alerts JSON string correctly', () => {
      const backendPrefs = {
        enabled_alerts: '["bundle_failed", "peer_offline", "new_peer"]',
      }

      const result = transformPrefsFromBackend(backendPrefs)

      expect(result.alert_types.bundle_failed).toBe(true)
      expect(result.alert_types.peer_offline).toBe(true)
      expect(result.alert_types.new_peer).toBe(true)
      expect(result.alert_types.bundle_deployed).toBe(false)
      expect(result.alert_types.peer_online).toBe(false)
    })

  test('handles missing enabled_alerts field', () => {
    const backendPrefs = {}

    const result = transformPrefsFromBackend(backendPrefs)

    // Should default all to true when no alerts are specified
    alertTypes.forEach(type => {
      expect(result.alert_types[type.key]).toBe(true)
    })
  })

  test('handles malformed JSON in enabled_alerts gracefully', () => {
    const backendPrefs = {
      enabled_alerts: 'not valid json',
    }

    const result = transformPrefsFromBackend(backendPrefs)

    // Should default all to true when JSON parsing fails
    expect(result).not.toBeNull()
    alertTypes.forEach(type => {
      expect(result.alert_types[type.key]).toBe(true)
    })
  })

  test('handles malformed JSON array in enabled_alerts', () => {
    const backendPrefs = {
      enabled_alerts: '[incomplete array',
    }

    const result = transformPrefsFromBackend(backendPrefs)

    // Should default all to true when JSON parsing fails
    expect(result).not.toBeNull()
    alertTypes.forEach(type => {
      expect(result.alert_types[type.key]).toBe(true)
    })
  })
})

  describe('transformPrefsToBackend (frontend to backend)', () => {
    test('transforms nested frontend structure to flat backend fields', () => {
      const frontendPrefs = {
        alert_types: {
          bundle_deployed: true,
          bundle_failed: false,
          peer_offline: true,
          peer_online: false,
          blocked_spike: true,
          new_peer: false,
        },
        quiet_hours: {
          enabled: true,
          start_time: '23:00',
          end_time: '07:00',
          timezone: 'Europe/London',
        },
        daily_digest: {
          enabled: true,
          time: '10:00',
        },
      }

      const result = transformPrefsToBackend(frontendPrefs)

      // Verify enabled_alerts is JSON stringified array of true keys
      expect(result.enabled_alerts).toBe('["bundle_deployed","peer_offline","blocked_spike"]')

      // Verify flat quiet_hours fields
      expect(result.quiet_hours_enabled).toBe(true)
      expect(result.quiet_hours_start).toBe('23:00')
      expect(result.quiet_hours_end).toBe('07:00')
      expect(result.quiet_hours_timezone).toBe('Europe/London')

      // Verify flat digest fields
      expect(result.digest_enabled).toBe(true)
      expect(result.digest_frequency).toBe('daily')
      expect(result.digest_time).toBe('10:00')
    })

    test('serializes enabled_alerts array to JSON string correctly', () => {
      const frontendPrefs = {
        alert_types: {
          bundle_deployed: true,
          peer_offline: true,
          new_peer: true,
        },
      }

      const result = transformPrefsToBackend(frontendPrefs)

      // Should be a valid JSON array string
      expect(typeof result.enabled_alerts).toBe('string')
      expect(() => JSON.parse(result.enabled_alerts)).not.toThrow()
      const parsed = JSON.parse(result.enabled_alerts)
      expect(Array.isArray(parsed)).toBe(true)
      expect(parsed).toContain('bundle_deployed')
      expect(parsed).toContain('peer_offline')
      expect(parsed).toContain('new_peer')
    })

    test('handles all alert types disabled', () => {
      const frontendPrefs = {
        alert_types: {
          bundle_deployed: false,
          bundle_failed: false,
          peer_offline: false,
          peer_online: false,
          blocked_spike: false,
          new_peer: false,
        },
      }

      const result = transformPrefsToBackend(frontendPrefs)

      expect(result.enabled_alerts).toBe('[]')
    })

    test('uses default values for missing nested structures', () => {
      const frontendPrefs = {}

      const result = transformPrefsToBackend(frontendPrefs)

      expect(result.quiet_hours_enabled).toBe(false)
      expect(result.quiet_hours_start).toBe('22:00')
      expect(result.quiet_hours_end).toBe('08:00')
      expect(result.quiet_hours_timezone).toBe('UTC')
      expect(result.digest_enabled).toBe(false)
      expect(result.digest_time).toBe('09:00')
    })

    test('preserves partial quiet_hours settings', () => {
      const frontendPrefs = {
        quiet_hours: {
          enabled: true,
          // start_time and end_time missing
        },
      }

      const result = transformPrefsToBackend(frontendPrefs)

      expect(result.quiet_hours_enabled).toBe(true)
      expect(result.quiet_hours_start).toBe('22:00') // default
      expect(result.quiet_hours_end).toBe('08:00') // default
    })
  })

  describe('backend schema integration', () => {
    test('transformPrefsToBackend output matches UpdateNotificationPreferencesRequest schema', () => {
      const frontendPrefs = {
        alert_types: {
          bundle_deployed: true,
          bundle_failed: false,
          peer_offline: true,
          peer_online: false,
          blocked_spike: false,
          new_peer: true,
        },
        quiet_hours: {
          enabled: true,
          start_time: '22:00',
          end_time: '08:00',
          timezone: 'America/New_York',
        },
        daily_digest: {
          enabled: true,
          time: '09:30',
        },
      }

      const result = transformPrefsToBackend(frontendPrefs)

      // Verify all expected backend fields are present
      const expectedFields = [
        'enabled_alerts',
        'quiet_hours_enabled',
        'quiet_hours_start',
        'quiet_hours_end',
        'quiet_hours_timezone',
        'digest_enabled',
        'digest_frequency',
        'digest_time',
      ]

      expectedFields.forEach(field => {
        expect(result).toHaveProperty(field)
      })

      // Verify field types match backend schema expectations
      // enabled_alerts: JSON string of array
      expect(typeof result.enabled_alerts).toBe('string')
      expect(() => JSON.parse(result.enabled_alerts)).not.toThrow()
      expect(Array.isArray(JSON.parse(result.enabled_alerts))).toBe(true)

      // quiet_hours_enabled: boolean
      expect(typeof result.quiet_hours_enabled).toBe('boolean')

      // quiet_hours_start: string time
      expect(typeof result.quiet_hours_start).toBe('string')
      expect(result.quiet_hours_start).toMatch(/^\d{2}:\d{2}$/)

      // quiet_hours_end: string time
      expect(typeof result.quiet_hours_end).toBe('string')
      expect(result.quiet_hours_end).toMatch(/^\d{2}:\d{2}$/)

      // quiet_hours_timezone: string
      expect(typeof result.quiet_hours_timezone).toBe('string')
      expect(result.quiet_hours_timezone.length).toBeGreaterThan(0)

      // digest_enabled: boolean
      expect(typeof result.digest_enabled).toBe('boolean')

      // digest_frequency: string
      expect(typeof result.digest_frequency).toBe('string')
      expect(result.digest_frequency).toBe('daily')

      // digest_time: string time
      expect(typeof result.digest_time).toBe('string')
      expect(result.digest_time).toMatch(/^\d{2}:\d{2}$/)
    })

    test('schema validation with all fields at default values', () => {
      const frontendPrefs = {}

      const result = transformPrefsToBackend(frontendPrefs)

      // Verify all expected fields are present even with empty input
      const expectedFields = [
        'enabled_alerts',
        'quiet_hours_enabled',
        'quiet_hours_start',
        'quiet_hours_end',
        'quiet_hours_timezone',
        'digest_enabled',
        'digest_frequency',
        'digest_time',
      ]

      expectedFields.forEach(field => {
        expect(result).toHaveProperty(field)
      })

      // Verify enabled_alerts is valid JSON array
      expect(() => JSON.parse(result.enabled_alerts)).not.toThrow()
      expect(Array.isArray(JSON.parse(result.enabled_alerts))).toBe(true)

      // Verify boolean fields have valid default values
      expect(typeof result.quiet_hours_enabled).toBe('boolean')
      expect(typeof result.digest_enabled).toBe('boolean')

      // Verify string fields have valid default values
      expect(typeof result.quiet_hours_start).toBe('string')
      expect(typeof result.quiet_hours_end).toBe('string')
      expect(typeof result.quiet_hours_timezone).toBe('string')
      expect(typeof result.digest_frequency).toBe('string')
      expect(typeof result.digest_time).toBe('string')
    })
  })

  describe('enabled_alerts serialization/deserialization round-trip', () => {
    test('round-trip preserves alert type selections', () => {
      // Start with backend data
      const backendPrefs = {
        enabled_alerts: '["bundle_deployed", "peer_offline", "blocked_spike"]',
        quiet_hours_enabled: false,
        digest_enabled: false,
      }

      // Transform to frontend
      const frontendPrefs = transformPrefsFromBackend(backendPrefs)

      // Transform back to backend
      const backToFrontend = transformPrefsToBackend(frontendPrefs)

      // Parse the enabled_alerts to compare
      const originalAlerts = JSON.parse(backendPrefs.enabled_alerts).sort()
      const roundTripAlerts = JSON.parse(backToFrontend.enabled_alerts).sort()

      expect(roundTripAlerts).toEqual(originalAlerts)
    })

    test('round-trip handles empty enabled_alerts', () => {
      const backendPrefs = {
        enabled_alerts: '[]',
      }

      const frontendPrefs = transformPrefsFromBackend(backendPrefs)
      const backToFrontend = transformPrefsToBackend(frontendPrefs)

      // Empty alerts should result in all true (default), which means all selected
      const roundTripAlerts = JSON.parse(backToFrontend.enabled_alerts)
      expect(roundTripAlerts.length).toBe(6) // All alert types
    })
  })

describe('transformSMTPFromBackend', () => {
    test('transforms backend config to frontend form state', () => {
      const smtpConfig = {
        host: 'smtp.example.com',
        port: 587,
        username: 'alerts',
        password_set: true,
        use_tls: true,
        from_address: 'alerts@example.com',
        enabled: true,
      }

      const result = transformSMTPFromBackend(smtpConfig)

      expect(result.host).toBe('smtp.example.com')
      expect(result.port).toBe(587)
      expect(result.username).toBe('alerts')
      expect(result.password).toBe('') // Password should never be populated
      expect(result.use_tls).toBe(true)
      expect(result.from_address).toBe('alerts@example.com')
      expect(result.enabled).toBe(true)
    })

    test('never populates password from backend', () => {
      const smtpConfig = {
        password: 'sensitive_password',
        password_set: true,
      }

      const result = transformSMTPFromBackend(smtpConfig)

      expect(result.password).toBe('')
    })

    test('handles null/undefined input', () => {
      const result = transformSMTPFromBackend(null)

      expect(result).toEqual({
        host: '',
        port: 587,
        username: '',
        password: '',
        use_tls: true,
        from_address: '',
        enabled: false,
      })
    })

    test('uses default values for missing fields', () => {
      const smtpConfig = {}

      const result = transformSMTPFromBackend(smtpConfig)

      expect(result.port).toBe(587)
      expect(result.use_tls).toBe(true)
      expect(result.enabled).toBe(false)
    })

    test('handles undefined boolean values with defaults', () => {
      const smtpConfig = {
        use_tls: undefined,
        enabled: undefined,
      }

      const result = transformSMTPFromBackend(smtpConfig)

      expect(result.use_tls).toBe(true) // Default
      expect(result.enabled).toBe(false) // Default
    })

    test('preserves explicit false values', () => {
      const smtpConfig = {
        use_tls: false,
        enabled: false,
      }

      const result = transformSMTPFromBackend(smtpConfig)

      expect(result.use_tls).toBe(false)
      expect(result.enabled).toBe(false)
    })
  })
})
