/**
 * useAuth — reads the current user's role from the Zustand auth store.
 *
 * NOTE: This is a client-side value only, used for UI gating.
 * Backend middleware enforces actual authorization.
 */
import { useAuthStore } from '../store'

export function useAuth() {
  const role = useAuthStore(s => s.role)
  return {
    role,
    isAdmin: role === 'admin',
    isEditor: role === 'admin' || role === 'editor',
    canEdit: role === 'admin' || role === 'editor',
  }
}
