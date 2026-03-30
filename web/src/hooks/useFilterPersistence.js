import { useState, useEffect, useCallback } from 'react'
import { useAuthStore } from '../store'

export function useFilterPersistence(pageKey, filterKey, defaultValue) {
  const username = useAuthStore(s => s.username)
  const storageKey = username ? `runic_${username}_${pageKey}_${filterKey}` : null

  const [value, setValue] = useState(() => {
    if (!storageKey) return defaultValue
    const saved = localStorage.getItem(storageKey)
    if (saved) {
      try { return JSON.parse(saved) } catch { return defaultValue }
    }
    return defaultValue
  })

  useEffect(() => {
    if (storageKey) {
      localStorage.setItem(storageKey, JSON.stringify(value))
    }
  }, [storageKey, value])

  const clearFilterPreference = useCallback(() => {
    if (storageKey) {
      localStorage.removeItem(storageKey)
    }
    setValue(defaultValue)
  }, [storageKey, defaultValue])

  return { value, setValue, clearFilterPreference }
}
