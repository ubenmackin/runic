import { create } from 'zustand'
import { setAuthFailureHandler, api, BASE } from '../api/client'

export const useAuthStore = create((set) => ({
  isAuthenticated: null,  // null = checking, true/false = known
  username: null,
  role: null,
  login: async () => useAuthStore.getState().checkAuth(),
  logout: async () => {
    try {
      await fetch(`${BASE}/auth/logout`, { method: 'POST', credentials: 'include' })
    } catch {
      // Intentionally ignore - state may not exist in localStorage
    }
    set({ isAuthenticated: false, username: null, role: null })
  },
  checkAuth: async () => {
    try {
      const user = await api.get('/auth/me')
      set({ isAuthenticated: true, username: user.username, role: user.role })
    } catch {
      set({ isAuthenticated: false, username: null, role: null })
    }
  },
}))

// Register auth failure handler so client.js can sync store on refresh failures
setAuthFailureHandler(() => useAuthStore.getState().logout())
