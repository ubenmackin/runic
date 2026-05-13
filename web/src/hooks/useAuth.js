/**
 * useAuth — reads the current user's role from the Zustand auth store.
 *
 * NOTE: This is a client-side value only, used for UI gating.
 * Backend middleware enforces actual authorization.
 */
import { useAuthStore } from '../store'

export function useAuth() {
  const role = useAuthStore(s => s.role)
  const isAdmin = role === 'admin'
  const isEditor = role === 'admin' || role === 'editor'
  return {
    role,
    isAdmin,
    isEditor,
    canEdit: isEditor,
  }
}
