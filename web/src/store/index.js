import { create } from 'zustand'
import { setTokens, clearTokens, setAuthFailureHandler, api } from '../api/client'

export const useAuthStore = create((set) => ({
  isAuthenticated: !!sessionStorage.getItem('runic_access_token'),
  login: (access, refresh) => {
    setTokens(access, refresh)
    set({ isAuthenticated: true })
  },
  logout: async () => {
    try {
      await api.post('/auth/logout', {})
    } catch (err) {
      // Ignore errors - we'll clear tokens regardless
      console.warn('Logout API call failed:', err.message)
    } finally {
      clearTokens()
      set({ isAuthenticated: false })
    }
  },
}))

// Register auth failure handler so client.js can sync store on refresh failures
setAuthFailureHandler(() => useAuthStore.getState().logout())
