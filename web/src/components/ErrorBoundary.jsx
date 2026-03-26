import { Component } from 'react'

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
    this.reset = this.reset.bind(this)
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error('ErrorBoundary caught:', error, errorInfo)
  }

  reset() {
    this.setState({ hasError: false, error: null })
  }

  render() {
    if (this.state.hasError) {
      // Use fallback prop if provided, otherwise use default UI
      if (this.props.fallback) {
        return this.props.fallback(this.state.error, this.reset)
      }

      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
          <div className="text-center space-y-4 p-8">
            <h1 className="text-2xl font-bold text-red-600">Something went wrong</h1>
            <p className="text-gray-600 dark:text-gray-400 max-w-md">
              {import.meta.env.DEV
                ? (this.state.error?.message || 'An unexpected error occurred.')
                : 'An unexpected error occurred. Please try again.'}
            </p>
            <div className="flex gap-3 justify-center">
              <button
                onClick={this.reset}
                className="px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg"
              >
                Try Again
              </button>
              <button
                onClick={() => window.location.reload()}
                className="px-4 py-2 bg-runic-600 hover:bg-runic-700 text-white text-sm font-medium rounded-lg"
              >
                Reload Page
              </button>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

// Route-specific error boundary with custom UI
export function RouteErrorBoundary({ children }) {
  return (
    <ErrorBoundary
      fallback={(error, reset) => (
        <div className="flex items-center justify-center p-8">
          <div className="text-center space-y-4 max-w-md">
            <h2 className="text-xl font-semibold text-red-600 dark:text-red-400">Page Error</h2>
            <p className="text-gray-600 dark:text-gray-400 text-sm">
              {import.meta.env.DEV
                ? (error?.message || 'Failed to load this page.')
                : 'This page encountered an error. Please try again.'}
            </p>
            <div className="flex gap-3 justify-center">
              <button
                onClick={reset}
                className="px-4 py-2 bg-runic-600 hover:bg-runic-700 text-white text-sm font-medium rounded-lg"
              >
                Retry
              </button>
            </div>
          </div>
        </div>
      )}
    >
      {children}
    </ErrorBoundary>
  )
}
