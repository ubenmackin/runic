import { useState, useEffect, useCallback, useRef } from 'react'

/**
 * Hook for persisting state in localStorage with lazy initialization.
 * Writes are debounced to avoid excessive storage operations on rapid updates.
 *
 * @param {string|null|undefined} key - Storage key (null/undefined disables persistence)
 * @param {*} defaultValue - Default value when no saved value exists
 * @param {number} debounceMs - Debounce interval for writes (default: 300ms)
 * @param {Function|null} migrate - Optional migration function applied to parsed value
 * @returns {[*, Function, Function]} - [value, setValue, clearValue]
 */
export function useLocalStorage(key, defaultValue, debounceMs = 300, migrate = null) {
  const storageKey = key ?? null

  const [value, setValue] = useState(() => {
    if (storageKey === null) return defaultValue
    const saved = localStorage.getItem(storageKey)
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
    if (storageKey === null) return

    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
    }

    timeoutRef.current = setTimeout(() => {
      localStorage.setItem(storageKey, JSON.stringify(valueRef.current))
    }, debounceMs)

    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current)
      }
    }
  }, [storageKey, value, debounceMs])

  const clearValue = useCallback(() => {
    if (storageKey !== null) {
      localStorage.removeItem(storageKey)
    }
    setValue(defaultValue)
  }, [storageKey, defaultValue])

  return [value, setValue, clearValue]
}

export default useLocalStorage
