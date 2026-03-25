import { createContext, useContext, useState, useEffect } from 'react'
import { api } from '../api/client'

const SetupContext = createContext(null)

export function SetupProvider({ children }) {
  const [needsSetup, setNeedsSetup] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    api.get('/setup')
      .then(data => {
        setNeedsSetup(data.needs_setup)
      })
      .catch(err => {
        setError(err)
        // Default to false on error to prevent infinite loops
        setNeedsSetup(false)
      })
      .finally(() => {
        setLoading(false)
      })
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
