import { toListArray, mapWrappedList, WRAPPED_LIST_KEYS } from './listUtils'
import { describe, test, expect, vi } from 'vitest'

describe('WRAPPED_LIST_KEYS', () => {
  test('exposes the supported wrapper keys', () => {
    expect(WRAPPED_LIST_KEYS).toEqual(['items', 'data', 'logs'])
  })
})

describe('toListArray', () => {
  test('returns a bare array as-is', () => {
    const list = [{ id: 1 }]
    expect(toListArray(list)).toBe(list)
  })

  test('unwraps the items key', () => {
    const items = [{ id: 1 }]
    expect(toListArray({ items, total: 1 })).toBe(items)
  })

  test('unwraps the data key', () => {
    const data = [{ id: 2 }]
    expect(toListArray({ data })).toBe(data)
  })

  test('unwraps the logs key', () => {
    const logs = [{ id: 3 }]
    expect(toListArray({ logs })).toBe(logs)
  })

  test('falls through non-array keys to the next known key', () => {
    const data = [{ id: 4 }]
    expect(toListArray({ items: null, data })).toBe(data)
    expect(toListArray({ items: 'nope', data: 42, logs: ['entry'] })).toEqual([
      'entry',
    ])
  })

  test('returns an empty array for unknown shapes', () => {
    expect(toListArray(null)).toEqual([])
    expect(toListArray(undefined)).toEqual([])
    expect(toListArray(42)).toEqual([])
    expect(toListArray('items')).toEqual([])
    expect(toListArray({})).toEqual([])
    expect(toListArray({ items: 'not-an-array' })).toEqual([])
  })
})

describe('mapWrappedList', () => {
  test('maps a bare array', () => {
    const list = [1, 2, 3]
    const mapFn = vi.fn((inner) => inner.map((n) => n * 2))
    expect(mapWrappedList(list, mapFn)).toEqual([2, 4, 6])
    expect(mapFn).toHaveBeenCalledWith(list)
  })

  test('maps the items wrapper and preserves other fields', () => {
    const cached = { items: [{ id: 1 }], total: 1 }
    const mapFn = (inner) => inner.map((item) => ({ ...item, seen: true }))
    const result = mapWrappedList(cached, mapFn)
    expect(result).toEqual({ items: [{ id: 1, seen: true }], total: 1 })
    expect(result).not.toBe(cached)
    expect(cached.items).toEqual([{ id: 1 }])
  })

  test('maps the data wrapper', () => {
    expect(
      mapWrappedList({ data: [1, 2] }, (inner) => inner.concat(3)),
    ).toEqual({ data: [1, 2, 3] })
  })

  test('maps the logs wrapper', () => {
    expect(
      mapWrappedList({ logs: ['a'] }, (inner) =>
        inner.map((value) => value.toUpperCase()),
      ),
    ).toEqual({ logs: ['A'] })
  })

  test('falls through non-array keys to the next known key', () => {
    const result = mapWrappedList({ items: null, data: [1] }, (inner) =>
      inner.map((n) => n + 1),
    )
    expect(result).toEqual({ items: null, data: [2] })
  })

  test('returns the original value when no list is found', () => {
    const cached = {}
    expect(mapWrappedList(cached, (inner) => inner)).toBe(cached)
    expect(mapWrappedList(null, (inner) => inner)).toBeNull()
    expect(mapWrappedList(undefined, (inner) => inner)).toBeUndefined()
    expect(mapWrappedList('items', (inner) => inner)).toBe('items')
    expect(mapWrappedList(42, (inner) => inner)).toBe(42)
    expect(mapWrappedList({ items: 'not-an-array' }, (inner) => inner)).toEqual({
      items: 'not-an-array',
    })
  })
})
