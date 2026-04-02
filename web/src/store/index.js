import { create } from 'zustand'
import { setTokens, clearTokens, setAuthFailureHandler, api } from '../api/client'

// decodeJwt decodes the JWT payload client-side for UI display purposes only.
// NOTE: This is NOT for security validation. Actual token validation is performed
// server-side by the auth middleware. The JWT signature is NOT verified here.
function decodeJwt(token) {
  try {
    const payload = token.split('.')[1]
    const decoded = JSON.parse(atob(payload))
    return {
      username: decoded.username || null,
      role: decoded.role || null,
    }
  } catch {
    return { username: null, role: null }
  }
}

function getUserFromToken() {
  const token = localStorage.getItem('runic_access_token')
  return token ? decodeJwt(token) : { username: null, role: null }
}

export const useAuthStore = create((set) => ({
  isAuthenticated: !!localStorage.getItem('runic_access_token'),
  username: getUserFromToken().username,
  role: getUserFromToken().role,
  login: (access, refresh) => {
    setTokens(access, refresh)
    const { username, role } = decodeJwt(access)
    set({ isAuthenticated: true, username, role })
  },
  logout: async () => {
    try {
      await api.post('/auth/logout', {})
    } catch (err) {
      // Ignore errors - we'll clear tokens regardless
      console.warn('Logout API call failed:', err.message)
    } finally {
      clearTokens()
      set({ isAuthenticated: false, username: null, role: null })
    }
  },
}))

// Register auth failure handler so client.js can sync store on refresh failures
setAuthFailureHandler(() => useAuthStore.getState().logout())
