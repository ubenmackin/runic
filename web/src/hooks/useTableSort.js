import { useCallback } from 'react'
import { useLocalStorage } from './useLocalStorage'
import { useCurrentUsername, buildStorageKey } from './useCurrentUsername'

export function useTableSort(pageKey, defaultSort) {
  const username = useCurrentUsername()
  const storageKey = buildStorageKey(username, pageKey, 'sort')
  const [sortConfig, setSortConfig, clearValue] = useLocalStorage(storageKey, defaultSort)

  const handleSort = useCallback((key) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key ? (prev.direction === 'asc' ? 'desc' : 'asc') : 'asc'
    }))
  }, [setSortConfig])

  const clearSortPreference = useCallback(() => {
    clearValue()
  }, [clearValue])

  return { sortConfig, setSortConfig, handleSort, clearSortPreference }
}
