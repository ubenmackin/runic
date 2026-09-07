/**
 * Shared helpers for normalizing paginated or wrapped list payloads.
 * API caches may hold a bare array or an object wrapping the array under
 * one of the known list keys, so reads and optimistic updates share these
 * helpers instead of duplicating the unwrap logic.
 */

export const WRAPPED_LIST_KEYS = ['items', 'data', 'logs']

/**
 * Unwrap a paginated/wrapped list payload into a plain array.
 * @param {*} payload - Bare array or object wrapping an array
 * @returns {Array} The inner array, or an empty array for unknown shapes
 */
export function toListArray(payload) {
  if (Array.isArray(payload)) return payload
  if (payload && typeof payload === 'object') {
    for (const key of WRAPPED_LIST_KEYS) {
      if (Array.isArray(payload[key])) return payload[key]
    }
  }
  return []
}

/**
 * Apply a list transform while preserving the cached wrapper shape.
 * @param {*} cached - Bare array or object wrapping an array
 * @param {Function} mapFn - Transform applied to the inner array
 * @returns {*} Transformed cache, or the original value when no list is found
 */
export function mapWrappedList(cached, mapFn) {
  if (Array.isArray(cached)) return mapFn(cached)
  if (cached && typeof cached === 'object') {
    for (const key of WRAPPED_LIST_KEYS) {
      if (Array.isArray(cached[key])) {
        return { ...cached, [key]: mapFn(cached[key]) }
      }
    }
  }
  return cached
}
