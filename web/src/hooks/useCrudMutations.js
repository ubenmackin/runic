import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { logger } from '../utils/logger'
import { mapWrappedList } from '../utils/listUtils'

// Normalize an entity id for optimistic-update comparison. Numeric and
// string forms of the same id compare equal, while null, undefined, empty
// strings and NaN never match so a bad id cannot clobber the cache.
function normalizeCrudId(id) {
  if (id === null || id === undefined) return null
  if (typeof id === 'number') {
    if (!Number.isInteger(id)) return null
    return String(id)
  }
  const str = String(id).trim()
  if (!str) return null
  return str
}

/**
 * Generic CRUD mutations with optimistic updates.
 *
 * @param {Object} config
 * @param {string} config.apiPath - API endpoint (e.g., '/services')
 * @param {Array} config.queryKey - React Query key for the entity
 * @param {Array} config.additionalInvalidations - Optional array of additional query keys to invalidate
 * @param {Function} config.onCreateSuccess - Optional callback on create success (e.g., close modal)
 * @param {Function} config.onUpdateSuccess - Optional callback on update success
 * @param {Function} config.onDeleteSuccess - Optional callback on delete success
 * @param {Function} config.setFormErrors - Optional setter for form errors
 * @param {Function} config.showToast - Optional toast function for error display
 * @param {Function} config.getId - Function to extract id from item (default: item => item.id)
 * @returns {Object} { createMutation, updateMutation, deleteMutation }
 */
export function useCrudMutations({
  apiPath,
  queryKey,
  additionalInvalidations = [],
  onCreateSuccess,
  onUpdateSuccess,
  onDeleteSuccess,
  setFormErrors,
  showToast,
  getId = (item) => item.id,
}) {
  const qc = useQueryClient()

  const createMutation = useMutation({
    mutationFn: (data) => api.post(apiPath, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey })
      additionalInvalidations.forEach(key => qc.invalidateQueries({ queryKey: key }))
      onCreateSuccess?.()
    },
    onError: (err) => {
      setFormErrors?.({ _general: err.message })
      showToast?.(err.message, 'error')
    },
  })

  const idsEqual = (a, b) => {
    const normA = normalizeCrudId(typeof a === 'object' && a !== null ? getId(a) : a)
    const normB = normalizeCrudId(b)
    if (normA === null || normB === null) return false
    return normA === normB
  }

  const mapCachedList = (old, mapFn, queryKeyForLog) => {
    const next = mapWrappedList(old, mapFn)
    if (next === old) {
      logger.warn(`useCrudMutations: expected array for queryKey ${JSON.stringify(queryKeyForLog)}, got ${Array.isArray(old) ? 'array' : typeof old}`)
    }
    return next
  }

  const updateMutation = useMutation({
    mutationFn: ({ id, data }) => api.put(`${apiPath}/${id}`, data),
    onMutate: async ({ id, data }) => {
      await qc.cancelQueries({ queryKey })
      await Promise.all(additionalInvalidations.map(key => qc.cancelQueries({ queryKey: key })))
      const previousData = qc.getQueryData(queryKey)
      qc.setQueryData(queryKey, old => mapCachedList(old,
        (list) => list.map(item => idsEqual(item, id) ? { ...item, ...data } : item),
        queryKey))
      return { previousData }
    },
    onError: (err, vars, context) => {
      if (context?.previousData !== undefined) {
        qc.setQueryData(queryKey, context.previousData)
      }
      setFormErrors?.({ _general: err.message })
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey })
      additionalInvalidations.forEach(key => qc.invalidateQueries({ queryKey: key }))
      onUpdateSuccess?.()
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => api.delete(`${apiPath}/${id}`),
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey })
      await Promise.all(additionalInvalidations.map(key => qc.cancelQueries({ queryKey: key })))
      const previousData = qc.getQueryData(queryKey)
      qc.setQueryData(queryKey, old => mapCachedList(old,
        (list) => list.filter(item => !idsEqual(item, id)),
        queryKey))
      return { previousData }
    },
    onError: (err, id, context) => {
      if (context?.previousData !== undefined) {
        qc.setQueryData(queryKey, context.previousData)
      }
      showToast?.(err.message, 'error')
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey })
      additionalInvalidations.forEach(key => qc.invalidateQueries({ queryKey: key }))
      onDeleteSuccess?.()
    },
  })

  return { createMutation, updateMutation, deleteMutation }
}
