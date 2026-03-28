import { create } from 'zustand'
import { setTokens, clearTokens, setAuthFailureHandler, api } from '../api/client'

// decodeJwt decodes the JWT payload client-side for UI display purposes only.
// NOTE: This is NOT for security validation. Actual token validation is performed
// server-side by the auth middleware. The JWT signature is NOT verified here.
function decodeJwt(token) {
  try {
    const payload = token.split('.')[1]
    const decoded = JSON.parse(atob(payload))
    return decoded.username || null
  } catch {
    return null
  }
}

function getUsernameFromToken() {
  const token = sessionStorage.getItem('runic_access_token')
  return token ? decodeJwt(token) : null
}

export const useAuthStore = create((set) => ({
  isAuthenticated: !!sessionStorage.getItem('runic_access_token'),
  username: getUsernameFromToken(),
  login: (access, refresh) => {
    setTokens(access, refresh)
    set({ isAuthenticated: true, username: decodeJwt(access) })
  },
  logout: async () => {
    try {
      await api.post('/auth/logout', {})
    } catch (err) {
      // Ignore errors - we'll clear tokens regardless
      console.warn('Logout API call failed:', err.message)
    } finally {
      clearTokens()
      set({ isAuthenticated: false, username: null })
    }
  },
}))

// Register auth failure handler so client.js can sync store on refresh failures
setAuthFailureHandler(() => useAuthStore.getState().logout())
