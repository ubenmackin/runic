import { computeDiff } from './diff'
import { describe, test, expect } from 'vitest'

describe('computeDiff', () => {
  test('empty strings', () => {
    expect(computeDiff('', '')).toBe('')
  })

  test('identical content', () => {
    const rules = 'line1\nline2\nline3'
    expect(computeDiff(rules, rules)).toBe(' line1\n line2\n line3')
  })

  test('complete replacement', () => {
    const oldRules = 'old1\nold2\nold3'
    const newRules = 'new1\nnew2\nnew3'
    const result = computeDiff(oldRules, newRules)
    expect(result).toContain('- old1')
    expect(result).toContain('+ new1')
  })

  test('addition only', () => {
    const oldRules = 'line1'
    const newRules = 'line1\nline2\nline3'
    const result = computeDiff(oldRules, newRules)
    expect(result).toContain(' line1')
    expect(result).toContain('+ line2')
    expect(result).toContain('+ line3')
  })

  test('removal only', () => {
    const oldRules = 'line1\nline2\nline3'
    const newRules = 'line1'
    const result = computeDiff(oldRules, newRules)
    expect(result).toContain(' line1')
    expect(result).toContain('- line2')
    expect(result).toContain('- line3')
  })
})
