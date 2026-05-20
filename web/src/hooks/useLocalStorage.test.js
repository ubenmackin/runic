import { renderHook, act } from '@testing-library/react'
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { useLocalStorage } from './useLocalStorage'

describe('useLocalStorage', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  test('returns default value when no saved value exists', () => {
    const { result } = renderHook(() => useLocalStorage('test-key', 'default'))
    expect(result.current[0]).toBe('default')
  })

  test('returns saved value from localStorage', () => {
    localStorage.setItem('test-key', JSON.stringify('saved'))
    const { result } = renderHook(() => useLocalStorage('test-key', 'default'))
    expect(result.current[0]).toBe('saved')
  })

  test('writes value to localStorage with debounce', () => {
    const { result } = renderHook(() => useLocalStorage('test-key', 'initial'))

    act(() => {
      result.current[1]('updated')
    })

    // Before debounce completes, nothing has been written yet
    // (the hook only writes when the value changes, not for the initial value)
    expect(localStorage.getItem('test-key')).toBeNull()

    // After debounce completes
    act(() => {
      vi.advanceTimersByTime(300)
    })

    expect(localStorage.getItem('test-key')).toBe(JSON.stringify('updated'))
  })

  test('clears value from localStorage', () => {
    localStorage.setItem('test-key', JSON.stringify('saved'))
    const { result } = renderHook(() => useLocalStorage('test-key', 'default'))

    act(() => {
      result.current[2]() // clearValue
    })

    expect(localStorage.getItem('test-key')).toBeNull()
    expect(result.current[0]).toBe('default')
  })

  test('disables persistence when key is null', () => {
    const { result } = renderHook(() => useLocalStorage(null, 'default'))
    expect(result.current[0]).toBe('default')

    act(() => {
      result.current[1]('updated')
    })
    act(() => {
      vi.advanceTimersByTime(300)
    })

    // Should not write to localStorage
    expect(localStorage.getItem('null')).toBeNull()
  })

  test('disables persistence when key is undefined', () => {
    const { result } = renderHook(() => useLocalStorage(undefined, 'default'))
    expect(result.current[0]).toBe('default')

    act(() => {
      result.current[1]('updated')
    })
    act(() => {
      vi.advanceTimersByTime(300)
    })

    // Should not write to localStorage
    expect(localStorage.getItem('undefined')).toBeNull()
  })

  test('handles null key in clearValue without error', () => {
    const { result } = renderHook(() => useLocalStorage(null, 'default'))

    act(() => {
      result.current[2]() // clearValue with null key
    })

    expect(result.current[0]).toBe('default')
  })

  test('applies migration function to saved value', () => {
    localStorage.setItem('test-key', JSON.stringify({ version: 1 }))
    const migrate = (data) => ({ ...data, version: 2, migrated: true })

    const { result } = renderHook(() => useLocalStorage('test-key', {}, 300, migrate))
    expect(result.current[0]).toEqual({ version: 2, migrated: true })
  })

  test('returns default value for invalid JSON in localStorage', () => {
    localStorage.setItem('test-key', 'not-valid-json{{{')
    const { result } = renderHook(() => useLocalStorage('test-key', 'default'))
    expect(result.current[0]).toBe('default')
  })

  test('uses custom debounce interval', () => {
    const { result } = renderHook(() => useLocalStorage('test-key', 'initial', 500))

    act(() => {
      result.current[1]('updated')
    })

    // Not yet written at 300ms
    act(() => {
      vi.advanceTimersByTime(300)
    })
    expect(localStorage.getItem('test-key')).toBeNull()

    // Written at 500ms
    act(() => {
      vi.advanceTimersByTime(200)
    })
    expect(localStorage.getItem('test-key')).toBe(JSON.stringify('updated'))
  })

  test('debounces rapid updates and writes only the latest value', () => {
    const { result } = renderHook(() => useLocalStorage('test-key', 'initial', 300))

    act(() => {
      result.current[1]('first')
    })
    act(() => {
      result.current[1]('second')
    })
    act(() => {
      result.current[1]('third')
    })

    act(() => {
      vi.advanceTimersByTime(300)
    })

    expect(localStorage.getItem('test-key')).toBe(JSON.stringify('third'))
  })

  test('treats empty string key as valid (not null-like)', () => {
    const { result } = renderHook(() => useLocalStorage('', 'default'))
    // Empty string is a valid key, should attempt localStorage operations
    expect(result.current[0]).toBe('default')

    act(() => {
      result.current[1]('updated')
    })
    act(() => {
      vi.advanceTimersByTime(300)
    })

    expect(localStorage.getItem('')).toBe(JSON.stringify('updated'))
  })
})
