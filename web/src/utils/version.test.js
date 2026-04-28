import { isAgentOutdated } from './version'
import { describe, test, expect } from 'vitest'

describe('isAgentOutdated', () => {
  test('returns false when peer matches latest', () => {
    expect(isAgentOutdated('1.10.0', '1.10.0')).toBe(false)
  })

  test('returns true when peer minor is less than latest', () => {
    expect(isAgentOutdated('1.9.0', '1.10.0')).toBe(true)
  })

  test('returns false when peer is newer than latest', () => {
    expect(isAgentOutdated('1.10.0', '1.9.0')).toBe(false)
  })

  test('returns true when peer major is less than latest', () => {
    expect(isAgentOutdated('1.10.0', '2.0.0')).toBe(true)
  })

  test('returns true when peer patch is less than latest', () => {
    expect(isAgentOutdated('1.9.0', '1.9.1')).toBe(true)
  })

  test('handles v prefix', () => {
    expect(isAgentOutdated('v1.9.0', '1.10.0')).toBe(true)
  })

  test('returns false for missing peerVersion', () => {
    expect(isAgentOutdated(null, '1.10.0')).toBe(false)
  })

  test('returns false for missing latestVersion', () => {
    expect(isAgentOutdated('1.10.0', null)).toBe(false)
  })
})
