import { useCallback } from 'react'
import { useToastContext } from './ToastContext'
import { createApiError, categorizeError, ErrorTypes } from '../utils/apiErrors'

/**
 * useApiError - Hook for standardized API error handling
 * 
 * Provides utilities for handling API errors consistently across the app.
 * Integrates with Toast notifications and the error utility functions.
 * 
 * @returns {Object} Error handling utilities
 */
export function useApiError() {
  const showToast = useToastContext()

  const handleError = useCallback((error, options = {}) => {
    const apiError = createApiError(error)
    
    showToast(
      options.title ? `${options.title}: ${apiError.message}` : apiError.message,
      'error'
    )

    return apiError
  }, [showToast])

  const handleMutationError = useCallback((error, setFormErrors, field = '_general') => {
    const apiError = createApiError(error)
    setFormErrors(prev => ({ ...prev, [field]: apiError.message }))
    return apiError
  }, [])

  const createErrorHandler = useCallback((options = {}) => {
    return (error) => {
      const apiError = createApiError(error)
      
      if (options.onError) {
        options.onError(apiError)
      } else if (options.setFormErrors) {
        options.setFormErrors(prev => ({ ...prev, _general: apiError.message }))
      } else {
        showToast(apiError.message, 'error')
      }

      return apiError
    }
  }, [showToast])

  const isAuthError = useCallback((error) => {
    return categorizeError(error) === ErrorTypes.AUTH
  }, [])

  const getErrorMessage = useCallback((error) => {
    return createApiError(error).message
  }, [])

  return {
    handleError,
    handleMutationError,
    createErrorHandler,
    isAuthError,
    getErrorMessage,
    createApiError,
    categorizeError,
  }
}

export default useApiError
