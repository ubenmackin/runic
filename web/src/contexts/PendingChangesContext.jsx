import { createContext, useContext } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { aggregatePendingChangesCount } from '../utils/pendingChanges'

const PendingChangesContext = createContext(null)

export function PendingChangesProvider({ children }) {
  // Single query for pending changes, shared across components
  const { data: pendingChanges, isLoading, error } = useQuery({
    queryKey: ['pending-changes'],
    queryFn: () => api.get('/pending-changes'),
    refetchInterval: 15000, // Refetch every 15 seconds
    refetchIntervalInBackground: false, // Don't poll when tab is hidden
    staleTime: 10000, // Consider data fresh for 10 seconds
  })

  // Aggregate total count using the utility function
  const totalPendingCount = aggregatePendingChangesCount(pendingChanges)

  const value = {
    pendingChanges,
    totalPendingCount,
    isLoading,
    error,
  }

  return <PendingChangesContext.Provider value={value}>{children}</PendingChangesContext.Provider>
}

export function usePendingChanges() {
  const context = useContext(PendingChangesContext)
  if (!context) {
    throw new Error('usePendingChanges must be used within PendingChangesProvider')
  }
  return context
}
