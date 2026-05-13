import { createContext, useContext, useState, useEffect } from 'react'
import { api } from '../api/client'

const SetupContext = createContext(null)

export function SetupProvider({ children }) {
  const [needsSetup, setNeedsSetup] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false

    api.get('/setup')
      .then(data => {
        if (!cancelled) setNeedsSetup(data.needs_setup)
      })
      .catch(err => {
        if (!cancelled) {
          setError(err)
          // Default to false on error to prevent infinite loops
          setNeedsSetup(false)
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [])

  const value = {
    needsSetup,
    loading,
    error
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
