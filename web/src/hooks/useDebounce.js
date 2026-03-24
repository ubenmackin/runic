import { useState, useEffect } from 'react'

/**
 * Hook to debounce a value - delays updating the returned value until after
 * the specified delay has elapsed since the last change.
 * @param {*} value - The value to debounce
 * @param {number} delay - Delay in milliseconds (default 400ms)
 * @returns {*} The debounced value
 */
export function useDebounce(value, delay = 400) {
  const [debouncedValue, setDebouncedValue] = useState(value)

  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedValue(value)
    }, delay)

    return () => {
      clearTimeout(timer)
    }
  }, [value, delay])

  return debouncedValue
}