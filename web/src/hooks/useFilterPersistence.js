import { useCallback } from 'react'
import { useLocalStorage } from './useLocalStorage'
import { useCurrentUsername, buildStorageKey } from './useCurrentUsername'

export function useFilterPersistence(pageKey, filterKey, defaultValue) {
  const username = useCurrentUsername()
  const storageKey = buildStorageKey(username, pageKey, filterKey)
  const [value, setValue, clearValue] = useLocalStorage(storageKey, defaultValue)

  const clearFilterPreference = useCallback(() => {
    clearValue()
  }, [clearValue])

  return { value, setValue, clearFilterPreference }
}
