import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'

/**
 * Generic CRUD mutations with optimistic updates.
 * 
 * @param {Object} config
 * @param {string} config.apiPath - API endpoint (e.g., '/services')
 * @param {Array} config.queryKey - React Query key for the entity
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
      onCreateSuccess?.()
    },
    onError: (err) => {
      setFormErrors?.({ _general: err.message })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }) => api.put(`${apiPath}/${id}`, data),
    onMutate: async ({ id, data }) => {
      await qc.cancelQueries({ queryKey })
      const previousData = qc.getQueryData(queryKey)
      qc.setQueryData(queryKey, old => old?.map(item => getId(item) === id ? { ...item, ...data } : item) || [])
      return { previousData }
    },
    onError: (err, vars, context) => {
      qc.setQueryData(queryKey, context?.previousData)
      setFormErrors?.({ _general: err.message })
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey })
      onUpdateSuccess?.()
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => api.delete(`${apiPath}/${id}`),
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey })
      const previousData = qc.getQueryData(queryKey)
      qc.setQueryData(queryKey, old => old?.filter(item => getId(item) !== id) || [])
      return { previousData }
    },
    onError: (err, id, context) => {
      qc.setQueryData(queryKey, context?.previousData)
      showToast?.(err.message, 'error')
    },
    onSettled: () => {
      onDeleteSuccess?.()
    },
  })

  return { createMutation, updateMutation, deleteMutation }
}
