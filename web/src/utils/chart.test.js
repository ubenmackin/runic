import { describe, test, expect } from 'vitest'
import { processHourlyData, drawChart } from './chart'

describe('processHourlyData', () => {
  test('returns 24 buckets for null/undefined logs', () => {
    const resultNull = processHourlyData(null)
    const resultUndef = processHourlyData(undefined)
    expect(resultNull.length).toBe(24)
    expect(resultUndef.length).toBe(24)
    // All buckets should have zero counts
    expect(resultNull.every(b => b.count === 0)).toBe(true)
  })

  test('returns 24 buckets with zero counts for empty logs', () => {
    const result = processHourlyData([])
    expect(result.length).toBe(24)
    expect(result.every(b => b.count === 0)).toBe(true)
  })

  test('groups logs by hour', () => {
    const logs = [
      { timestamp: '2024-01-01T10:30:00Z', action: 'BLOCK' },
      { timestamp: '2024-01-01T10:45:00Z', action: 'BLOCK' },
      { timestamp: '2024-01-01T11:00:00Z', action: 'DROP' },
    ]
    const result = processHourlyData(logs)
    expect(result.length).toBe(24)
  })

  test('handles logs without timestamps', () => {
    const logs = [
      { action: 'BLOCK' },
      { timestamp: null, action: 'DROP' },
    ]
    const result = processHourlyData(logs)
    expect(Array.isArray(result)).toBe(true)
    expect(result.length).toBe(24)
  })
})

describe('drawChart', () => {
  test('does not throw with valid parameters', () => {
    const canvas = document.createElement('canvas')
    const ctx = canvas.getContext('2d')
    expect(() => {
      drawChart(ctx, 400, 200, [], null)
    }).not.toThrow()
  })

  test('does not throw with null context', () => {
    expect(() => {
      drawChart(null, 400, 200, [], null)
    }).not.toThrow()
  })

  test('draws chart with data', () => {
    const canvas = document.createElement('canvas')
    const ctx = canvas.getContext('2d')
    const data = [
      { label: '10AM', count: 5 },
      { label: '11AM', count: 3 },
    ]
    expect(() => {
      drawChart(ctx, 400, 200, data, null)
    }).not.toThrow()
  })
})