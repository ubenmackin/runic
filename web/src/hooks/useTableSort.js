import { useState, useEffect, useCallback } from 'react'
import { useAuthStore } from '../store'

export function useTableSort(pageKey, defaultSort) {
  const username = useAuthStore(s => s.username)
  const storageKey = username ? `runic_${username}_${pageKey}_sort` : null

  const [sortConfig, setSortConfig] = useState(() => {
    if (!storageKey) return defaultSort
    const saved = localStorage.getItem(storageKey)
    if (saved) {
      try { return JSON.parse(saved) } catch { return defaultSort }
    }
    return defaultSort
  })

  useEffect(() => {
    if (storageKey) {
      localStorage.setItem(storageKey, JSON.stringify(sortConfig))
    }
  }, [storageKey, sortConfig])

  const handleSort = useCallback((key) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key ? (prev.direction === 'asc' ? 'desc' : 'asc') : 'asc'
    }))
  }, [])

  const clearSortPreference = useCallback(() => {
    if (storageKey) {
      localStorage.removeItem(storageKey)
    }
    setSortConfig(defaultSort)
  }, [storageKey, defaultSort])

  return { sortConfig, setSortConfig, handleSort, clearSortPreference }
}
