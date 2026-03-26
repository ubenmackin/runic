import { AlertCircle, RefreshCw, Wifi, WifiOff, Lock, Search, AlertTriangle, Server, HelpCircle } from 'lucide-react'
import { ErrorTypes } from '../utils/apiErrors'

/**
 * ApiErrorDisplay - Consistent API error display component
 * 
 * Shows user-friendly error messages with appropriate icons and actions.
 * Supports dark mode and provides retry functionality.
 * 
 * @param {Object} props
 * @param {Object|string} props.error - Error object from API call or error message string
 * @param {Function} props.onRetry - Optional callback for retry button
 * @param {string} props.className - Additional CSS classes
 * @param {boolean} props.compact - Use compact variant (for inline display)
 * @param {boolean} props.showIcon - Show error icon (default: true)
 */
export default function ApiErrorDisplay({ 
  error, 
  onRetry, 
  className = '', 
  compact = false,
  showIcon = true 
}) {
  if (!error) return null

  // Extract error data
  const errorData = typeof error === 'object' && error.message 
    ? error 
    : { message: typeof error === 'string' ? error : 'An error occurred', type: 'unknown' }

  const { message, type, recoverable, suggestedAction } = errorData

  // Get appropriate icon based on error type
  const getIcon = () => {
    switch (type) {
      case ErrorTypes.NETWORK:
        return WifiOff
      case ErrorTypes.AUTH:
        return Lock
      case ErrorTypes.NOT_FOUND:
        return Search
      case ErrorTypes.PERMISSION:
        return Lock
      case ErrorTypes.SERVER:
        return Server
      case ErrorTypes.VALIDATION:
        return AlertTriangle
      default:
        return AlertCircle
    }
  }

  const Icon = getIcon()

  // Compact variant for inline errors (e.g., in form fields)
  if (compact) {
    return (
      <div className={`flex items-center gap-2 text-red-600 dark:text-red-400 text-sm ${className}`}>
        {showIcon && <AlertCircle className="w-4 h-4 flex-shrink-0" />}
        <span>{message}</span>
        {onRetry && recoverable !== false && (
          <button
            onClick={onRetry}
            className="ml-auto text-runic-600 hover:text-runic-700 dark:text-runic-400 font-medium flex items-center gap-1"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Retry
          </button>
        )}
      </div>
    )
  }

  // Full variant for page-level or section-level errors
  return (
    <div className={`flex items-center justify-center p-8 ${className}`}>
      <div className="text-center space-y-4 max-w-md">
        {/* Icon */}
        {showIcon && (
          <div className="flex justify-center">
            <div className="p-3 bg-red-100 dark:bg-red-900/30 rounded-full">
              <Icon className="w-8 h-8 text-red-600 dark:text-red-400" />
            </div>
          </div>
        )}

        {/* Message */}
        <div className="space-y-2">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            {type === ErrorTypes.NETWORK ? 'Connection Error' : 
             type === ErrorTypes.AUTH ? 'Authentication Required' :
             type === ErrorTypes.NOT_FOUND ? 'Not Found' :
             type === ErrorTypes.SERVER ? 'Server Error' :
             'Error'}
          </h3>
          <p className="text-gray-600 dark:text-gray-400 text-sm">
            {message}
          </p>
          {suggestedAction && (
            <p className="text-gray-500 dark:text-gray-500 text-xs">
              {suggestedAction}
            </p>
          )}
        </div>

        {/* Actions */}
        <div className="flex gap-3 justify-center">
          {onRetry && recoverable !== false && (
            <button
              onClick={onRetry}
              className="flex items-center gap-2 px-4 py-2 bg-runic-600 hover:bg-runic-700 text-white text-sm font-medium rounded-lg transition-colors"
            >
              <RefreshCw className="w-4 h-4" /> Try Again
            </button>
          )}
          {type === ErrorTypes.AUTH && (
            <a
              href="/login"
              className="px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg transition-colors"
            >
              Log In
            </a>
          )}
        </div>
      </div>
    </div>
  )
}

/**
 * ApiErrorInline - Simplified inline error display for forms and tables
 * 
 * @param {Object} props
 * @param {string} props.message - Error message to display
 * @param {Function} props.onRetry - Optional retry callback
 */
export function ApiErrorInline({ message, onRetry }) {
  return (
    <ApiErrorDisplay 
      error={{ message, type: 'unknown' }} 
      compact 
      showIcon={false}
      onRetry={onRetry}
    />
  )
}

/**
 * ApiErrorCard - Card-style error display for dashboard sections
 * 
 * @param {Object} props
 * @param {string} props.title - Section title
 * @param {Object|string} props.error - Error to display
 * @param {Function} props.onRetry - Retry callback
 */
export function ApiErrorCard({ title, error, onRetry }) {
  if (!error) return null

  const errorData = typeof error === 'object' && error.message 
    ? error 
    : { message: typeof error === 'string' ? error : 'An error occurred' }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
      {title && (
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">{title}</h3>
      )}
      <ApiErrorDisplay error={errorData} onRetry={onRetry} />
    </div>
  )
}

/**
 * NetworkStatus - Connection status indicator with retry
 * 
 * @param {Object} props
 * @param {boolean} props.connected - Whether connected to server
 * @param {Function} props.onRetry - Retry connection callback
 */
export function NetworkStatus({ connected, onRetry }) {
  return (
    <div className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm ${
      connected 
        ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400' 
        : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400'
    }`}>
      {connected ? (
        <>
          <Wifi className="w-4 h-4" />
          <span>Connected</span>
        </>
      ) : (
        <>
          <WifiOff className="w-4 h-4" />
          <span>Disconnected</span>
          {onRetry && (
            <button 
              onClick={onRetry}
              className="ml-2 hover:underline font-medium"
            >
              Reconnect
            </button>
          )}
        </>
      )}
    </div>
  )
}
