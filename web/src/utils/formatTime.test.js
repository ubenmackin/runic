import { formatRelativeTime } from './formatTime'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

describe('formatRelativeTime', () => {
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
    test('returns "Never" for null', () => {
      expect(formatRelativeTime(null)).toBe('Never')
    })

    test('returns "Never" for undefined', () => {
      expect(formatRelativeTime(undefined)).toBe('Never')
    })

    test('returns "Never" for empty string', () => {
      expect(formatRelativeTime('')).toBe('Never')
    })

    test('returns "Never" for false', () => {
      expect(formatRelativeTime(false)).toBe('Never')
    })

    test('returns formatted date for invalid date string', () => {
      // Invalid dates are parsed as "Invalid Date" which returns NaN for getTime()
      // The function will return a formatted date string via toLocaleDateString()
      const result = formatRelativeTime('not-a-date')
      // Invalid Date produces NaN, which results in very large diff values
      // The function will return toLocaleDateString() for dates >= 7 days
      expect(typeof result).toBe('string')
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

    test('returns "1 minute ago" for exactly 60 seconds ago', () => {
      const oneMinuteAgo = new Date(mockNow.getTime() - 60 * 1000).toISOString()
      expect(formatRelativeTime(oneMinuteAgo)).toBe('1 minute ago')
    })

    test('returns "5 minutes ago" for 5 minutes ago', () => {
      const fiveMinutesAgo = new Date(mockNow.getTime() - 5 * 60 * 1000).toISOString()
      expect(formatRelativeTime(fiveMinutesAgo)).toBe('5 minutes ago')
    })

    test('returns "59 minutes ago" for 59 minutes ago', () => {
      const fiftyNineMinutesAgo = new Date(mockNow.getTime() - 59 * 60 * 1000).toISOString()
      expect(formatRelativeTime(fiftyNineMinutesAgo)).toBe('59 minutes ago')
    })

    test('returns "1 hour ago" for exactly 60 minutes ago', () => {
      const oneHourAgo = new Date(mockNow.getTime() - 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(oneHourAgo)).toBe('1 hour ago')
    })

    test('returns "2 hours ago" for 2 hours ago', () => {
      const twoHoursAgo = new Date(mockNow.getTime() - 2 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(twoHoursAgo)).toBe('2 hours ago')
    })

    test('returns "23 hours ago" for 23 hours ago', () => {
      const twentyThreeHoursAgo = new Date(mockNow.getTime() - 23 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(twentyThreeHoursAgo)).toBe('23 hours ago')
    })

    test('returns "1 day ago" for exactly 24 hours ago', () => {
      const oneDayAgo = new Date(mockNow.getTime() - 24 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(oneDayAgo)).toBe('1 day ago')
    })

    test('returns "3 days ago" for 3 days ago', () => {
      const threeDaysAgo = new Date(mockNow.getTime() - 3 * 24 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(threeDaysAgo)).toBe('3 days ago')
    })

    test('returns "6 days ago" for 6 days ago', () => {
      const sixDaysAgo = new Date(mockNow.getTime() - 6 * 24 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(sixDaysAgo)).toBe('6 days ago')
    })
  })

  describe('date format for older dates', () => {
    test('returns formatted date for 7 days ago', () => {
      const sevenDaysAgo = new Date(mockNow.getTime() - 7 * 24 * 60 * 60 * 1000)
      const result = formatRelativeTime(sevenDaysAgo.toISOString())
      // toLocaleDateString() format depends on locale, just verify it's a string
      expect(typeof result).toBe('string')
      expect(result).not.toBe('Just now')
      expect(result).not.toContain('ago')
    })

    test('returns formatted date for 30 days ago', () => {
      const thirtyDaysAgo = new Date(mockNow.getTime() - 30 * 24 * 60 * 60 * 1000)
      const result = formatRelativeTime(thirtyDaysAgo.toISOString())
      expect(typeof result).toBe('string')
      expect(result).not.toContain('ago')
    })
  })

  describe('various date formats', () => {
    test('handles ISO 8601 format', () => {
      const isoDate = new Date(mockNow.getTime() - 5 * 60 * 1000).toISOString()
      expect(formatRelativeTime(isoDate)).toBe('5 minutes ago')
    })

    test('handles Unix timestamp (milliseconds)', () => {
      const timestamp = mockNow.getTime() - 5 * 60 * 1000
      expect(formatRelativeTime(timestamp)).toBe('5 minutes ago')
    })

    test('handles Date objects', () => {
      const date = new Date(mockNow.getTime() - 5 * 60 * 1000)
      expect(formatRelativeTime(date)).toBe('5 minutes ago')
    })

    test('handles common date string format', () => {
      // Create a date 5 minutes before mockNow
      const date = new Date(mockNow.getTime() - 5 * 60 * 1000)
      const dateString = date.toString()
      expect(formatRelativeTime(dateString)).toBe('5 minutes ago')
    })
  })

  describe('singular vs plural forms', () => {
    test('uses singular "minute" for 1 minute', () => {
      const oneMinuteAgo = new Date(mockNow.getTime() - 60 * 1000).toISOString()
      expect(formatRelativeTime(oneMinuteAgo)).toBe('1 minute ago')
    })

    test('uses plural "minutes" for 2 minutes', () => {
      const twoMinutesAgo = new Date(mockNow.getTime() - 2 * 60 * 1000).toISOString()
      expect(formatRelativeTime(twoMinutesAgo)).toBe('2 minutes ago')
    })

    test('uses singular "hour" for 1 hour', () => {
      const oneHourAgo = new Date(mockNow.getTime() - 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(oneHourAgo)).toBe('1 hour ago')
    })

    test('uses plural "hours" for 2 hours', () => {
      const twoHoursAgo = new Date(mockNow.getTime() - 2 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(twoHoursAgo)).toBe('2 hours ago')
    })

    test('uses singular "day" for 1 day', () => {
      const oneDayAgo = new Date(mockNow.getTime() - 24 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(oneDayAgo)).toBe('1 day ago')
    })

    test('uses plural "days" for 2 days', () => {
      const twoDaysAgo = new Date(mockNow.getTime() - 2 * 24 * 60 * 60 * 1000).toISOString()
      expect(formatRelativeTime(twoDaysAgo)).toBe('2 days ago')
    })
  })

  describe('edge cases', () => {
    test('handles future dates correctly', () => {
      // Future dates will result in negative diff
      const futureDate = new Date(mockNow.getTime() + 5 * 60 * 1000).toISOString()
      const result = formatRelativeTime(futureDate)
      // Negative diff means "Just now" since diffSeconds < 0 < 60
      expect(result).toBe('Just now')
    })

    test('handles exactly zero time difference', () => {
      expect(formatRelativeTime(mockNow.toISOString())).toBe('Just now')
    })

    test('handles very large time differences', () => {
      const oneYearAgo = new Date(mockNow.getTime() - 365 * 24 * 60 * 60 * 1000)
      const result = formatRelativeTime(oneYearAgo.toISOString())
      expect(typeof result).toBe('string')
      expect(result).not.toContain('ago')
    })
  })
})
