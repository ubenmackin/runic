import { useAuthStore } from '../store'

/**
 * Returns the current username from the auth store.
 * Used to namespace localStorage keys per user.
 *
 * @returns {string|null} Current username or null if not authenticated
 */
export function useCurrentUsername() {
  return useAuthStore(s => s.username)
}

/**
 * Builds a namespaced localStorage key for the given user, page, and setting.
 * @param {string|null} username - Current username
 * @param {string} pageKey - Page identifier (e.g., 'peers', 'policies')
 * @param {string} settingKey - Setting identifier (e.g., 'filter', 'sort')
 * @returns {string|null} Storage key, or null if username is null
 */
export function buildStorageKey(username, pageKey, settingKey) {
  return username ? `runic_${username}_${pageKey}_${settingKey}` : null
}

export default useCurrentUsername
