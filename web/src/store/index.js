import { create } from 'zustand'
import { setTokens, clearTokens, setAuthFailureHandler } from '../api/client'

export const useAuthStore = create((set) => ({
  isAuthenticated: !!sessionStorage.getItem('runic_access_token'),
  login: (access, refresh) => {
    setTokens(access, refresh)
    set({ isAuthenticated: true })
  },
  logout: () => {
    clearTokens()
    set({ isAuthenticated: false })
  },
}))

// Register auth failure handler so client.js can sync store on refresh failures
setAuthFailureHandler(() => useAuthStore.getState().logout())
