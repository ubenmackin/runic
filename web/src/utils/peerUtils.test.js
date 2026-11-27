import { parseCompositePeerValue } from './peerUtils'
import { describe, test, expect } from 'vitest'

describe('parseCompositePeerValue', () => {
  test('returns null for non-string values', () => {
    expect(parseCompositePeerValue(5)).toBeNull()
    expect(parseCompositePeerValue(null)).toBeNull()
    expect(parseCompositePeerValue(undefined)).toBeNull()
    expect(parseCompositePeerValue({ id: 1 })).toBeNull()
  })

  test('returns null for values without the peer prefix', () => {
    expect(parseCompositePeerValue('group:5')).toBeNull()
    expect(parseCompositePeerValue('peer')).toBeNull()
  })

  test('returns null for missing or invalid ids', () => {
    expect(parseCompositePeerValue('peer:')).toBeNull()
    expect(parseCompositePeerValue('peer:abc')).toBeNull()
    expect(parseCompositePeerValue('peer:-1')).toBeNull()
    expect(parseCompositePeerValue('peer:0')).toBeNull()
  })

  test('returns null for ids outside the safe integer range', () => {
    expect(parseCompositePeerValue(`peer:${'9'.repeat(400)}`)).toBeNull()
  })

  test('parses an id without an IP', () => {
    expect(parseCompositePeerValue('peer:1')).toEqual({ id: 1, ip: null })
    expect(parseCompositePeerValue('peer:42:')).toEqual({ id: 42, ip: null })
    expect(parseCompositePeerValue('peer: 7 ')).toEqual({ id: 7, ip: null })
  })

  test('parses a composite IPv4 value', () => {
    expect(parseCompositePeerValue('peer:5:10.20.10.20')).toEqual({
      id: 5,
      ip: '10.20.10.20',
    })
  })

  test('trims whitespace around the attached IP', () => {
    expect(parseCompositePeerValue('peer:5: 10.20.10.20 ')).toEqual({
      id: 5,
      ip: '10.20.10.20',
    })
  })

  test('parses a composite IPv6 value', () => {
    expect(parseCompositePeerValue('peer:9:2001:db8::1')).toEqual({
      id: 9,
      ip: '2001:db8::1',
    })
  })

  test('returns null for invalid attached IPs', () => {
    expect(parseCompositePeerValue('peer:5:not-an-ip')).toBeNull()
    expect(parseCompositePeerValue('peer:5:999.1.1.1')).toBeNull()
  })
})
