import { createContext, useContext } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'

const SetupContext = createContext(null)

export function SetupProvider({ children }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['setup'],
    queryFn: ({ signal }) => api.get('/setup', signal),
    staleTime: 60_000,
    retry: 1,
    // Default needsSetup to false on error to prevent infinite redirect loops
    select: (d) => d?.needs_setup ?? false,
  })

  const value = {
    needsSetup: error ? false : (isLoading ? null : data),
    loading: isLoading,
    error,
  }

  return <SetupContext.Provider value={value}>{children}</SetupContext.Provider>
}

export function useSetup() {
  const context = useContext(SetupContext)
  if (!context) {
    throw new Error('useSetup must be used within SetupProvider')
  }
  return context
}
