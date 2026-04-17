/**
 * Parse error messages from various error types into user-friendly strings
 * @param {Error|Response|string} error - The error to parse
 * @returns {string} User-friendly error message
 */
export function parseApiError(error) {
  if (typeof error === 'string') {
    return error
  }

  if (error instanceof Error) {
    if (error.name === 'TypeError' && error.message === 'Failed to fetch') {
      return 'Unable to connect to server. Please check your network connection.'
    }

    if (error.name === 'AbortError') {
      return 'Request timed out. Please try again.'
    }

    if (error.message === 'Session expired. Please log in again.') {
      return error.message
    }

    return error.message || 'An unexpected error occurred.'
  }

  if (error instanceof Response) {
    return getResponseErrorMessage(error)
  }

  if (error?.error?.message) {
    return error.error.message
  }

  if (error?.message) {
    return error.message
  }

  return 'An unexpected error occurred.'
}

// Get user-friendly message for HTTP status codes
export function getStatusMessage(status) {
  const statusMessages = {
    400: 'Invalid request. Please check your input and try again.',
    401: 'Authentication required. Please log in again.',
    403: 'You do not have permission to perform this action.',
    404: 'The requested resource was not found.',
    409: 'This action conflicts with existing data. Please refresh and try again.',
    422: 'Invalid data provided. Please check your input.',
    429: 'Too many requests. Please wait a moment and try again.',
    500: 'Server error. Please try again later.',
    502: 'Server is temporarily unavailable. Please try again.',
    503: 'Service temporarily unavailable. Please try again later.',
    504: 'Request timed out. Please try again.',
  }

  return statusMessages[status] || `Request failed with status ${status}.`
}

/**
 * Extract error message from Response object
 * @param {Response} response - Fetch Response object
 * @returns {Promise<string>} User-friendly error message
 */
export async function getResponseErrorMessage(response) {
  const statusMessage = getStatusMessage(response.status)

  try {
    const body = await response.json()
    
    // API returns { error: { message: string, code?: string } }
    if (body?.error?.message) {
      if (body.error.code === 'UNAUTHORIZED' || response.status === 401) {
        return 'Session expired. Please log in again.'
      }
      return body.error.message
    }

    return statusMessage
  } catch {
    return statusMessage
  }
}

/**
 * Determine if an error is recoverable (user can retry)
 * @param {Error|Response} error - The error to check
 * @returns {boolean} True if the error is recoverable
 */
export function isRecoverableError(error) {
  if (error?.name === 'TypeError' && error?.message === 'Failed to fetch') {
    return true
  }

  if (error?.name === 'AbortError') {
    return true
  }

  if (error instanceof Response && error.status >= 500) {
    return true
  }

  if (error instanceof Response && error.status === 429) {
    return true
  }

  if (error instanceof Response && error.status === 401) {
    return false
  }

  if (error instanceof Response && error.status === 403) {
    return false
  }

  return true
}

/**
 * Get suggested action for an error
 * @param {Error|Response} error - The error to analyze
 * @returns {string} Suggested action for the user
 */
export function getSuggestedAction(error) {
  const message = parseApiError(error)

  if (message.includes('network') || message.includes('connect')) {
    return 'Check your internet connection and try again.'
  }

  if (message.includes('timed out') || message.includes('timeout')) {
    return 'The server is taking too long to respond. Please try again.'
  }

  if (message.includes('Session expired') || message.includes('log in')) {
    return 'Click here to log in again.'
  }

  if (message.includes('permission') || message.includes('not authorized')) {
    return 'Contact your administrator if you believe this is an error.'
  }

  if (isRecoverableError(error)) {
    return 'Please try again.'
  }

  return 'If this problem persists, contact support.'
}

/**
 * Error type constants for categorizing errors
 */
export const ErrorTypes = {
  NETWORK: 'network',
  AUTH: 'auth',
  VALIDATION: 'validation',
  NOT_FOUND: 'not_found',
  PERMISSION: 'permission',
  SERVER: 'server',
  UNKNOWN: 'unknown',
}

/**
 * Categorize an error into a type
 * @param {Error|Response} error - The error to categorize
 * @returns {string} Error type from ErrorTypes
 */
export function categorizeError(error) {
  if (error?.name === 'TypeError' && error?.message === 'Failed to fetch') {
    return ErrorTypes.NETWORK
  }

  if (error instanceof Response) {
    if (error.status === 401) return ErrorTypes.AUTH
    if (error.status === 403) return ErrorTypes.PERMISSION
    if (error.status === 404) return ErrorTypes.NOT_FOUND
    if (error.status === 422 || error.status === 400) return ErrorTypes.VALIDATION
    if (error.status >= 500) return ErrorTypes.SERVER
  }

  const message = parseApiError(error)
  if (message.includes('Session expired') || message.includes('log in')) {
    return ErrorTypes.AUTH
  }

  return ErrorTypes.UNKNOWN
}

/**
 * Create an error object with metadata for use with ApiErrorDisplay
 * @param {Error|Response|string} error - The original error
 * @returns {Object} Structured error object
 */
export function createApiError(error) {
  return {
    original: error,
    message: parseApiError(error),
    type: categorizeError(error),
    recoverable: isRecoverableError(error),
    suggestedAction: getSuggestedAction(error),
  }
}
