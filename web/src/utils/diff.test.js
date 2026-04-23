import { computeDiff } from './diff'
import { describe, test, expect } from 'vitest'

describe('computeDiff', () => {
  test('empty strings', () => {
    expect(computeDiff('', '')).toBe('')
  })

  test('empty string vs single newline', () => {
    // "\n".split('\n') => ['', ''], filtered to [''] by removing trailing empty
    // Go splitLines("\n") => [""]
    // Both should produce the same result: a diff of one empty line
    const result = computeDiff('', '\n')
    expect(result).toBe('+ ')
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

  test('middle insertion', () => {
    const oldRules = 'a\nb\nc'
    const newRules = 'a\nX\nb\nc'
    const result = computeDiff(oldRules, newRules)
    const lines = result.split('\n')
    expect(lines).toEqual([' a', '+ X', ' b', ' c'])
  })

  test('middle deletion', () => {
    const oldRules = 'a\nX\nb\nc'
    const newRules = 'a\nb\nc'
    const result = computeDiff(oldRules, newRules)
    const lines = result.split('\n')
    expect(lines).toEqual([' a', '- X', ' b', ' c'])
  })

  test('complex reordering with additions and deletions', () => {
    const oldRules = 'alpha\nbeta\ngamma\ndelta'
    const newRules = 'alpha\ngamma\nepsilon\nzeta\ndelta'
    const result = computeDiff(oldRules, newRules)
    const lines = result.split('\n')
    expect(lines).toContain(' alpha')
    expect(lines).toContain('- beta')
    expect(lines).toContain(' gamma')
    expect(lines).toContain('+ epsilon')
    expect(lines).toContain('+ zeta')
    expect(lines).toContain(' delta')
    // Ensure beta is not shown as unchanged
    expect(lines).not.toContain(' beta')
  })

  test('all new content', () => {
    const oldRules = ''
    const newRules = 'a\nb\nc'
    const result = computeDiff(oldRules, newRules)
    const lines = result.split('\n')
    expect(lines).toEqual(['+ a', '+ b', '+ c'])
  })

  test('all removed content', () => {
    const oldRules = 'a\nb\nc'
    const newRules = ''
    const result = computeDiff(oldRules, newRules)
    const lines = result.split('\n')
    expect(lines).toEqual(['- a', '- b', '- c'])
  })

  test('null inputs treated as empty', () => {
    expect(computeDiff(null, 'a')).toBe('+ a')
    expect(computeDiff('a', null)).toBe('- a')
    expect(computeDiff(null, null)).toBe('')
  })
})
