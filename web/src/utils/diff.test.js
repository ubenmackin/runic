import { computeDiff, computeSmartDiff } from './diff'
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

describe('computeSmartDiff', () => {
  test('identical content returns []', () => {
    const rules = 'line1\nline2\nline3'
    expect(computeSmartDiff(rules, rules)).toEqual([])
  })

  test('addition only returns add entries with correct section header', () => {
    const oldRules = '# --- Section A\nalpha\nbeta'
    const newRules = '# --- Section A\nalpha\ngamma\ndelta'
    const result = computeSmartDiff(oldRules, newRules)
    // LCS pairs beta→gamma as a change; delta is a standalone add
    expect(result).toEqual([
      { type: 'section-header', line: '# --- Section A', sectionHeader: '# --- Section A' },
      { type: 'change', oldLine: 'beta', newLine: 'gamma', sectionHeader: '# --- Section A' },
      { type: 'add', line: 'delta', sectionHeader: '# --- Section A' },
    ])
  })

  test('removal only returns remove entries', () => {
    const oldRules = '# --- Section A\nalpha\nbeta\ngamma'
    const newRules = '# --- Section A\nalpha'
    const result = computeSmartDiff(oldRules, newRules)
    expect(result).toEqual([
      { type: 'section-header', line: '# --- Section A', sectionHeader: '# --- Section A' },
      { type: 'remove', line: 'beta', sectionHeader: '# --- Section A' },
      { type: 'remove', line: 'gamma', sectionHeader: '# --- Section A' },
    ])
  })

  test('change (old line replaced by new line) returns change entry', () => {
    const oldRules = '# --- Section A\nalpha\nbeta'
    const newRules = '# --- Section A\nalpha\nBETA'
    const result = computeSmartDiff(oldRules, newRules)
    expect(result).toEqual([
      { type: 'section-header', line: '# --- Section A', sectionHeader: '# --- Section A' },
      { type: 'change', oldLine: 'beta', newLine: 'BETA', sectionHeader: '# --- Section A' },
    ])
  })

  test('multiple consecutive removes then adds pairs them as changes, extras as standalone', () => {
    const oldRules = '# --- Section A\nremoved1\nremoved2'
    const newRules = '# --- Section A\nadded1\nadded2\nadded3'
    const result = computeSmartDiff(oldRules, newRules)
    // 2 removes + 3 adds → 2 change entries (paired 1:1) + 1 standalone add
    expect(result).toEqual([
      { type: 'section-header', line: '# --- Section A', sectionHeader: '# --- Section A' },
      { type: 'change', oldLine: 'removed1', newLine: 'added1', sectionHeader: '# --- Section A' },
      { type: 'change', oldLine: 'removed2', newLine: 'added2', sectionHeader: '# --- Section A' },
      { type: 'add', line: 'added3', sectionHeader: '# --- Section A' },
    ])
  })

  test('suppresses unchanged lines', () => {
    const oldRules = '# --- Section A\nalpha\nbeta\ngamma'
    const newRules = '# --- Section A\nalpha\nBETA\ngamma'
    const result = computeSmartDiff(oldRules, newRules)
    // Only the changed line should appear; alpha and gamma are unchanged and suppressed
    expect(result).toEqual([
      { type: 'section-header', line: '# --- Section A', sectionHeader: '# --- Section A' },
      { type: 'change', oldLine: 'beta', newLine: 'BETA', sectionHeader: '# --- Section A' },
    ])
  })

  test('only shows section headers for sections with changes', () => {
    const oldRules =
      '# --- Section A\nalpha\nbeta\n# --- Section B\ngamma\ndelta'
    const newRules =
      '# --- Section A\nalpha\nbeta\n# --- Section B\ngamma\nDELTA'
    const result = computeSmartDiff(oldRules, newRules)
    // Section A has no changes, so its header should NOT appear
    // Section B has a change, so its header SHOULD appear
    expect(result).toEqual([
      { type: 'section-header', line: '# --- Section B', sectionHeader: '# --- Section B' },
      { type: 'change', oldLine: 'delta', newLine: 'DELTA', sectionHeader: '# --- Section B' },
    ])
  })

  test('empty old rules and new rules with sections', () => {
    const oldRules = ''
    const newRules = '# --- Section A\nalpha\nbeta\n# --- Section B\ngamma'
    const result = computeSmartDiff(oldRules, newRules)
    // All lines are additions. Section headers that are added should be 'add' entries,
    // NOT 'section-header' entries (since they're added, not unchanged headers).
    expect(result).toEqual([
      { type: 'add', line: '# --- Section A', sectionHeader: null },
      { type: 'add', line: 'alpha', sectionHeader: null },
      { type: 'add', line: 'beta', sectionHeader: null },
      { type: 'add', line: '# --- Section B', sectionHeader: null },
      { type: 'add', line: 'gamma', sectionHeader: null },
    ])
  })

  test('null inputs returns []', () => {
    expect(computeSmartDiff(null, null)).toEqual([])
    expect(computeSmartDiff(null, '')).toEqual([])
    expect(computeSmartDiff('', null)).toEqual([])
  })

  test('real bundle-like content with multiple sections and mixed changes', () => {
    const oldRules = [
      '# --- Network Rules',
      'block 10.0.0.0/8',
      'allow 192.168.1.1',
      'allow 172.16.0.0/12',
      '# --- DNS Rules',
      'forward 8.8.8.8',
      'forward 8.8.4.4',
      '# --- Firewall Rules',
      'allow tcp/443',
      'deny udp/53',
    ].join('\n')

    const newRules = [
      '# --- Network Rules',
      'block 10.0.0.0/8',
      'allow 192.168.1.100',
      'allow 172.16.0.0/12',
      'block 192.168.0.0/16',
      '# --- DNS Rules',
      'forward 8.8.8.8',
      'forward 1.1.1.1',
      '# --- Firewall Rules',
      'allow tcp/443',
      'allow tcp/80',
    ].join('\n')

    const result = computeSmartDiff(oldRules, newRules)

    // Network Rules: "allow 192.168.1.1" → "allow 192.168.1.100" (change), "block 192.168.0.0/16" (add)
    // DNS Rules: "forward 8.8.4.4" → "forward 1.1.1.1" (change)
    // Firewall Rules: "deny udp/53" → "allow tcp/80" (change)
    expect(result).toEqual([
      { type: 'section-header', line: '# --- Network Rules', sectionHeader: '# --- Network Rules' },
      { type: 'change', oldLine: 'allow 192.168.1.1', newLine: 'allow 192.168.1.100', sectionHeader: '# --- Network Rules' },
      { type: 'add', line: 'block 192.168.0.0/16', sectionHeader: '# --- Network Rules' },
      { type: 'section-header', line: '# --- DNS Rules', sectionHeader: '# --- DNS Rules' },
      { type: 'change', oldLine: 'forward 8.8.4.4', newLine: 'forward 1.1.1.1', sectionHeader: '# --- DNS Rules' },
      { type: 'section-header', line: '# --- Firewall Rules', sectionHeader: '# --- Firewall Rules' },
      { type: 'change', oldLine: 'deny udp/53', newLine: 'allow tcp/80', sectionHeader: '# --- Firewall Rules' },
    ])
  })
})

