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

  /**
   * Handle an API error by showing a toast notification
   * @param {Error|string} error - The error to handle
   * @param {Object} options - Options for error handling
   * @param {string} options.title - Optional title for the toast
   * @param {Function} options.onRetry - Optional retry callback
   * @returns {Object} Structured error object
   */
  const handleError = useCallback((error, options = {}) => {
    const apiError = createApiError(error)
    
    // Show toast for the error
    showToast(
      options.title ? `${options.title}: ${apiError.message}` : apiError.message,
      'error'
    )

    return apiError
  }, [showToast])

  /**
   * Handle a mutation error with form error state
   * @param {Error} error - The error from the mutation
   * @param {Function} setFormErrors - React state setter for form errors
   * @param {string} field - Field name for the error (default: '_general')
   */
  const handleMutationError = useCallback((error, setFormErrors, field = '_general') => {
    const apiError = createApiError(error)
    setFormErrors(prev => ({ ...prev, [field]: apiError.message }))
    return apiError
  }, [])

  /**
   * Create an onError handler for useQuery/useMutation
   * @param {Object} options - Configuration options
   * @param {Function} options.setFormErrors - Optional form errors setter
   * @param {Function} options.onError - Optional custom error handler
   * @returns {Function} Error handler function
   */
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

  /**
   * Check if an error requires re-authentication
   * @param {Error} error - The error to check
   * @returns {boolean} True if re-authentication is needed
   */
  const isAuthError = useCallback((error) => {
    return categorizeError(error) === ErrorTypes.AUTH
  }, [])

  /**
   * Get user-friendly error message without showing toast
   * @param {Error|string} error - The error to parse
   * @returns {string} User-friendly error message
   */
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
