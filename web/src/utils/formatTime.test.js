import { formatRelativeTime } from './formatTime'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

describe('formatRelativeTime', () => {
  // Default return for null/undefined is em dash per updated spec
  const NULL_RETURN = '\u2014'
  let mockNow

  beforeEach(() => {
    // Mock current time to a fixed point for consistent testing
    mockNow = new Date('2024-01-15T12:00:00Z')
    vi.useFakeTimers()
    vi.setSystemTime(mockNow)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  describe('handles invalid dates', () => {
    test('returns "—" for null', () => {
      expect(formatRelativeTime(null)).toBe(NULL_RETURN)
    })

    test('returns "—" for undefined', () => {
      expect(formatRelativeTime(undefined)).toBe(NULL_RETURN)
    })

    test('returns "—" for empty string', () => {
      expect(formatRelativeTime('')).toBe(NULL_RETURN)
    })

    test('returns "—" for false', () => {
      expect(formatRelativeTime(false)).toBe(NULL_RETURN)
    })

    test('returns "—" for invalid date string', () => {
      // Invalid Date produces NaN, which should be handled gracefully
      const result = formatRelativeTime('not-a-date')
      expect(result).toBe(NULL_RETURN)
    })
  })

  describe('relative time formatting', () => {
    test('returns "Just now" for times less than 60 seconds ago', () => {
      const thirtySecondsAgo = new Date(mockNow.getTime() - 30 * 1000).toISOString()
      expect(formatRelativeTime(thirtySecondsAgo)).toBe('Just now')
    })

    test('returns "Just now" for exactly 59 seconds ago', () => {
      const fiftyNineSecondsAgo = new Date(mockNow.getTime() - 59 * 1000).toISOString()
      expect(formatRelativeTime(fiftyNineSecondsAgo)).toBe('Just now')
    })

    test('returns "1 min ago" for exactly 60 seconds ago', () => {
      const oneMinuteAgo = new Date(mockNow.getTime() - 60 * 1000).toISOString()
      expect(formatRelativeTime(oneMinuteAgo)).toBe('1 min ago')
    })

    test('returns "5 min ago" for 5 minutes ago', () => {
      const fiveMinutesAgo = new Date(mockNow.getTime() - 5 * 60 * 1000).toISOString()
      expect(formatRelativeTime(fiveMinutesAgo)).toBe('5 min ago')
    })

    test('returns "59 min ago" for 59 minutes ago', () => {
      const fiftyNineMinutesAgo = new Date(mockNow.getTime() - 59 * 60 * 1000).toISOString()
      expect(formatRelativeTime(fiftyNineMinutesAgo)).toBe('59 min ago')
    })

    test('returns "1h ago" for exactly 60 minutes ago', () => {
      const oneHourAgo = new Date(mockNow.getTime() - 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(oneHourAgo)).toBe('1h ago')
    })

    test('returns "2h ago" for 2 hours ago', () => {
      const twoHoursAgo = new Date(mockNow.getTime() - 2 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(twoHoursAgo)).toBe('2h ago')
    })

    test('returns "23h ago" for 23 hours ago', () => {
      const twentyThreeHoursAgo = new Date(mockNow.getTime() - 23 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(twentyThreeHoursAgo)).toBe('23h ago')
    })

    test('returns "1d ago" for exactly 24 hours ago', () => {
      const oneDayAgo = new Date(mockNow.getTime() - 24 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(oneDayAgo)).toBe('1d ago')
    })

    test('returns "3d ago" for 3 days ago', () => {
      const threeDaysAgo = new Date(mockNow.getTime() - 3 * 24 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(threeDaysAgo)).toBe('3d ago')
    })

    test('returns "6d ago" for 6 days ago', () => {
      const sixDaysAgo = new Date(mockNow.getTime() - 6 * 24 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(sixDaysAgo)).toBe('6d ago')
    })
  })

  describe('date format for older dates', () => {
    test('returns "7d ago" for 7 days ago', () => {
      const sevenDaysAgo = new Date(mockNow.getTime() - 7 * 24 * 60 * 60 * 1000)
      const result = formatRelativeTime(sevenDaysAgo.toISOString())
      expect(result).toBe('7d ago')
    })

    test('returns "30d ago" for 30 days ago', () => {
      const thirtyDaysAgo = new Date(mockNow.getTime() - 30 * 24 * 60 * 60 * 1000)
      const result = formatRelativeTime(thirtyDaysAgo.toISOString())
      expect(result).toBe('30d ago')
    })
  })

  describe('various date formats', () => {
    test('handles ISO 8601 format', () => {
      const isoDate = new Date(mockNow.getTime() - 5 * 60 * 1000).toISOString()
      expect(formatRelativeTime(isoDate)).toBe('5 min ago')
    })

    test('handles Unix timestamp (milliseconds)', () => {
      const timestamp = mockNow.getTime() - 5 * 60 * 1000
      expect(formatRelativeTime(timestamp)).toBe('5 min ago')
    })

    test('handles Date objects', () => {
      const date = new Date(mockNow.getTime() - 5 * 60 * 1000)
      expect(formatRelativeTime(date)).toBe('5 min ago')
    })

    test('handles common date string format', () => {
      // Create a date 5 minutes before mockNow
      const date = new Date(mockNow.getTime() - 5 * 60 * 1000)
      const dateString = date.toString()
      expect(formatRelativeTime(dateString)).toBe('5 min ago')
    })
  })

  describe('singular vs plural forms', () => {
    test('uses "1 min ago" for 1 minute', () => {
      const oneMinuteAgo = new Date(mockNow.getTime() - 60 * 1000).toISOString()
      expect(formatRelativeTime(oneMinuteAgo)).toBe('1 min ago')
    })

    test('uses "2 min ago" for 2 minutes', () => {
      const twoMinutesAgo = new Date(mockNow.getTime() - 2 * 60 * 1000).toISOString()
      expect(formatRelativeTime(twoMinutesAgo)).toBe('2 min ago')
    })

    test('uses "1h ago" for 1 hour', () => {
      const oneHourAgo = new Date(mockNow.getTime() - 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(oneHourAgo)).toBe('1h ago')
    })

    test('uses "2h ago" for 2 hours', () => {
      const twoHoursAgo = new Date(mockNow.getTime() - 2 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(twoHoursAgo)).toBe('2h ago')
    })

    test('uses "1d ago" for 1 day', () => {
      const oneDayAgo = new Date(mockNow.getTime() - 24 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(oneDayAgo)).toBe('1d ago')
    })

    test('uses "2d ago" for 2 days', () => {
      const twoDaysAgo = new Date(mockNow.getTime() - 2 * 24 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(twoDaysAgo)).toBe('2d ago')
    })
  })

  describe('SQLite datetime format handling', () => {
    test('handles SQLite format string "5 min ago"', () => {
      // SQLite format: 5 minutes before mockNow (2024-01-15T12:00:00Z)
      expect(formatRelativeTime('2024-01-15 11:55:00')).toBe('5 min ago')
    })

    test('handles SQLite format string "1h ago"', () => {
      // SQLite format: 1 hour before mockNow
      expect(formatRelativeTime('2024-01-15 11:00:00')).toBe('1h ago')
    })

    test('handles SQLite format string "Just now"', () => {
      // SQLite format: 30 seconds before mockNow
      expect(formatRelativeTime('2024-01-15 11:59:30')).toBe('Just now')
    })

    test('handles SQLite format string for older dates', () => {
      // SQLite format: 3 days before mockNow
      expect(formatRelativeTime('2024-01-12 12:00:00')).toBe('3d ago')
    })

    test('ISO 8601 strings with Z suffix still work (backward compatibility)', () => {
      // Standard ISO 8601: 5 minutes before mockNow
      const fiveMinutesAgo = new Date(mockNow.getTime() - 5 * 60 * 1000).toISOString()
      expect(formatRelativeTime(fiveMinutesAgo)).toBe('5 min ago')
    })

    test('SQLite format with different hours/minutes', () => {
      // SQLite format: 2 hours before mockNow
      expect(formatRelativeTime('2024-01-15 10:00:00')).toBe('2h ago')
    })
  })

  describe('edge cases', () => {
    test('handles future dates correctly', () => {
      // Future dates should show "in X min"
      const futureDate = new Date(mockNow.getTime() + 5 * 60 * 1000).toISOString()
      const result = formatRelativeTime(futureDate)
      expect(result).toBe('in 5 min')
    })

    test('handles future dates with hours', () => {
      const futureDate = new Date(mockNow.getTime() + 3 * 60 * 60 * 1000).toISOString()
      const result = formatRelativeTime(futureDate)
      expect(result).toBe('in 3h')
    })

    test('handles future dates with days', () => {
      const futureDate = new Date(mockNow.getTime() + 2 * 24 * 60 * 60 * 1000).toISOString()
      const result = formatRelativeTime(futureDate)
      expect(result).toBe('in 2d')
    })

    test('handles exactly zero time difference', () => {
      expect(formatRelativeTime(mockNow.toISOString())).toBe('Just now')
    })

    test('handles very large time differences', () => {
      const oneYearAgo = new Date(mockNow.getTime() - 365 * 24 * 60 * 60 * 1000)
      const result = formatRelativeTime(oneYearAgo.toISOString())
      expect(result).toBe('365d ago')
    })
  })
})
