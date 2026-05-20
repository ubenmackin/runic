import { useState, useEffect, useCallback, useRef } from 'react'

/**
 * Hook for persisting state in localStorage with lazy initialization.
 * Writes are debounced to avoid excessive storage operations on rapid updates.
 *
 * @param {string|null} key - Storage key (null disables persistence)
 * @param {*} defaultValue - Default value when no saved value exists
 * @param {number} debounceMs - Debounce interval for writes (default: 300ms)
 * @param {Function|null} migrate - Optional migration function applied to parsed value
 * @returns {[*, Function, Function]} - [value, setValue, clearValue]
 */
export function useLocalStorage(key, defaultValue, debounceMs = 300, migrate = null) {
  const [value, setValue] = useState(() => {
    if (!key) return defaultValue
    const saved = localStorage.getItem(key)
    if (saved) {
      try {
        let parsed = JSON.parse(saved)
        if (migrate) parsed = migrate(parsed)
        return parsed
      } catch { return defaultValue }
    }
    return defaultValue
  })

  const timeoutRef = useRef(null)
  const valueRef = useRef(value)

  // Keep valueRef in sync
  useEffect(() => {
    valueRef.current = value
  }, [value])

  // Debounced write to localStorage
  useEffect(() => {
    if (!key) return

    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
    }

    timeoutRef.current = setTimeout(() => {
      localStorage.setItem(key, JSON.stringify(valueRef.current))
    }, debounceMs)

    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current)
      }
    }
  }, [key, value, debounceMs])

  const clearValue = useCallback(() => {
    if (key) {
      localStorage.removeItem(key)
    }
    setValue(defaultValue)
  }, [key, defaultValue])

  return [value, setValue, clearValue]
}

export default useLocalStorage
