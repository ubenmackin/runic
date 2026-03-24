import { Component } from 'react'

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error('ErrorBoundary caught:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
          <div className="text-center space-y-4 p-8">
            <h1 className="text-2xl font-bold text-red-600">Something went wrong</h1>
            <p className="text-gray-600 dark:text-gray-400 max-w-md">
              {import.meta.env.DEV
                ? (this.state.error?.message || 'An unexpected error occurred.')
                : 'An unexpected error occurred. Please try again.'}
            </p>
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-runic-600 hover:bg-runic-700 text-white text-sm font-medium rounded-lg"
            >
              Reload Page
            </button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
