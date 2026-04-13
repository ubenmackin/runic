import { renderHook, act } from '@testing-library/react'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { useDebounce } from './useDebounce'

describe('useDebounce', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  test('returns initial value immediately', () => {
    const { result } = renderHook(() => useDebounce('initial', 500))

    expect(result.current).toBe('initial')
  })

  test('debounces rapid value changes', () => {
    const { result, rerender } = renderHook(
      ({ value, delay }) => useDebounce(value, delay),
      { initialProps: { value: 'first', delay: 500 } }
    )

    // Initial value is returned immediately
    expect(result.current).toBe('first')

    // Change value multiple times rapidly
    rerender({ value: 'second', delay: 500 })
    rerender({ value: 'third', delay: 500 })
    rerender({ value: 'fourth', delay: 500 })

    // Value should still be initial before timer completes
    expect(result.current).toBe('first')

    // Advance timers but not enough to complete debounce
    act(() => {
      vi.advanceTimersByTime(250)
    })

    // Still the initial value
    expect(result.current).toBe('first')

    // Advance timers to complete debounce
    act(() => {
      vi.advanceTimersByTime(250)
    })

    // Now should have the latest value
    expect(result.current).toBe('fourth')
  })

  test('uses default delay of 400ms', () => {
    const { result, rerender } = renderHook(
      ({ value }) => useDebounce(value),
      { initialProps: { value: 'initial' } }
    )

    expect(result.current).toBe('initial')

    rerender({ value: 'updated' })

    // Before default delay
    act(() => {
      vi.advanceTimersByTime(399)
    })
    expect(result.current).toBe('initial')

    // After default delay
    act(() => {
      vi.advanceTimersByTime(1)
    })
    expect(result.current).toBe('updated')
  })

  test('cancels on unmount', () => {
    const { result, unmount, rerender } = renderHook(
      ({ value, delay }) => useDebounce(value, delay),
      { initialProps: { value: 'initial', delay: 500 } }
    )

    expect(result.current).toBe('initial')

    // Change value
    rerender({ value: 'changed', delay: 500 })

    // Unmount before timer completes
    unmount()

    // Advance timers past the delay - no state update should occur
    act(() => {
      vi.advanceTimersByTime(500)
    })

    // Test passes if no error is thrown (cleanup ran successfully)
    // We can't check result.current after unmount as it would cause an error
  })

  test('resets timer when value changes before delay completes', () => {
    const { result, rerender } = renderHook(
      ({ value, delay }) => useDebounce(value, delay),
      { initialProps: { value: 'first', delay: 500 } }
    )

    // Change value
    rerender({ value: 'second', delay: 500 })

    // Advance 300ms (not enough to complete)
    act(() => {
      vi.advanceTimersByTime(300)
    })

    // Change value again - should reset timer
    rerender({ value: 'third', delay: 500 })

    // Advance another 300ms - still not enough since timer was reset
    act(() => {
      vi.advanceTimersByTime(300)
    })

    // Should still be initial value
    expect(result.current).toBe('first')

    // Advance to complete the reset timer
    act(() => {
      vi.advanceTimersByTime(200)
    })

    // Now should be updated
    expect(result.current).toBe('third')
  })

  test('handles delay changes', () => {
    const { result, rerender } = renderHook(
      ({ value, delay }) => useDebounce(value, delay),
      { initialProps: { value: 'initial', delay: 500 } }
    )

    expect(result.current).toBe('initial')

    // Change value and delay
    rerender({ value: 'updated', delay: 200 })

    // Should use new delay
    act(() => {
      vi.advanceTimersByTime(200)
    })

    expect(result.current).toBe('updated')
  })

  test('handles primitive values', () => {
    // Number
    const { result: numberResult, rerender: rerenderNumber } = renderHook(
      ({ value }) => useDebounce(value, 100),
      { initialProps: { value: 0 } }
    )

    rerenderNumber({ value: 42 })
    act(() => {
      vi.advanceTimersByTime(100)
    })
    expect(numberResult.current).toBe(42)

    // Boolean
    const { result: boolResult, rerender: rerenderBool } = renderHook(
      ({ value }) => useDebounce(value, 100),
      { initialProps: { value: false } }
    )

    rerenderBool({ value: true })
    act(() => {
      vi.advanceTimersByTime(100)
    })
    expect(boolResult.current).toBe(true)

    // Null
    const { result: nullResult, rerender: rerenderNull } = renderHook(
      ({ value }) => useDebounce(value, 100),
      { initialProps: { value: 'something' } }
    )

    rerenderNull({ value: null })
    act(() => {
      vi.advanceTimersByTime(100)
    })
    expect(nullResult.current).toBe(null)
  })

  test('handles object values', () => {
    const initialObj = { name: 'initial' }
    const updatedObj = { name: 'updated' }

    const { result, rerender } = renderHook(
      ({ value }) => useDebounce(value, 100),
      { initialProps: { value: initialObj } }
    )

    expect(result.current).toBe(initialObj)

    rerender({ value: updatedObj })
    act(() => {
      vi.advanceTimersByTime(100)
    })

    expect(result.current).toBe(updatedObj)
  })
})
