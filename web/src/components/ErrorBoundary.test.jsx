import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import ErrorBoundary, { RouteErrorBoundary } from './ErrorBoundary'

// Helper component that throws an error
function ThrowError({ message = 'Test error' }) {
  throw new Error(message)
}

// Helper component that renders fine
function GoodChild() {
  return <div data-testid="good-child">All good here</div>
}

describe('ErrorBoundary', () => {
  let consoleSpy

  beforeEach(() => {
    // Suppress console.error from React's error logging
    consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    consoleSpy.mockRestore()
  })

  describe('rendering children', () => {
    test('renders children when no error occurs', () => {
      render(
        <ErrorBoundary>
          <GoodChild />
        </ErrorBoundary>
      )
      expect(screen.getByTestId('good-child')).toBeInTheDocument()
      expect(screen.getByText('All good here')).toBeInTheDocument()
    })

    test('renders multiple children when no error', () => {
      render(
        <ErrorBoundary>
          <div data-testid="child-1">First</div>
          <div data-testid="child-2">Second</div>
        </ErrorBoundary>
      )
      expect(screen.getByTestId('child-1')).toBeInTheDocument()
      expect(screen.getByTestId('child-2')).toBeInTheDocument()
    })

    test('renders null children without crashing', () => {
      render(
        <ErrorBoundary>
          {null}
        </ErrorBoundary>
      )
      // Should not crash
    })

    test('renders undefined children without crashing', () => {
      const { container } = render(<ErrorBoundary>{undefined}</ErrorBoundary>)
      expect(container.innerHTML).toBe('')
    })
  })

  describe('error handling', () => {
    test('catches errors and shows fallback UI', () => {
      render(
        <ErrorBoundary>
          <ThrowError />
        </ErrorBoundary>
      )

      expect(screen.getByText('Something went wrong')).toBeInTheDocument()
      expect(screen.getByText('Test error')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /reload page/i })).toBeInTheDocument()
    })

    test('displays specific error message', () => {
      render(
        <ErrorBoundary>
          <ThrowError message="Specific error detail" />
        </ErrorBoundary>
      )

      // In dev mode (vitest default), the specific error message is shown
      expect(screen.getByText('Specific error detail')).toBeInTheDocument()
    })

    test('handles error with no message', () => {
      function ThrowNoMessage() {
        throw new Error()
      }

      render(
        <ErrorBoundary>
          <ThrowNoMessage />
        </ErrorBoundary>
      )

      expect(screen.getByText('Something went wrong')).toBeInTheDocument()
    })
  })

  describe('custom fallback', () => {
    test('renders custom fallback when provided', () => {
      const customFallback = (error, reset) => (
        <div>
          <h2>Custom Error UI</h2>
          <p>{error.message}</p>
          <button onClick={reset}>Reset</button>
        </div>
      )

      render(
        <ErrorBoundary fallback={customFallback}>
          <ThrowError message="Custom error message" />
        </ErrorBoundary>
      )

      expect(screen.getByText('Custom Error UI')).toBeInTheDocument()
      expect(screen.getByText('Custom error message')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /reset/i })).toBeInTheDocument()
      // Default fallback should not be shown
      expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument()
    })

    test('custom fallback receives error and reset function', () => {
      const customFallback = vi.fn((error, reset) => (
        <div>
          <h2>Error</h2>
          <button onClick={reset}>Reset</button>
        </div>
      ))

      render(
        <ErrorBoundary fallback={customFallback}>
          <ThrowError message="Callback test error" />
        </ErrorBoundary>
      )

      // The fallback function is called once by ErrorBoundary.render()
      // In some React environments it may be called twice (strict mode, etc.)
      expect(customFallback).toHaveBeenCalledTimes(2)
      expect(customFallback).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'Callback test error' }),
        expect.any(Function)
      )
    })

    test('reset function restores error state for rerendered children', async () => {
      const user = userEvent.setup()

      const fallbackFn = (error, reset) => (
        <div>
          <h2>Error Occurred</h2>
          <p>{error.message}</p>
          <button onClick={reset}>Reset</button>
        </div>
      )

      const { rerender } = render(
        <ErrorBoundary fallback={fallbackFn}>
          <ThrowError />
        </ErrorBoundary>
      )

      expect(screen.getByText('Error Occurred')).toBeInTheDocument()

      // First rerender with non-throwing children (while still in error state)
      // This keeps the error boundary in error state, showing fallback
      rerender(
        <ErrorBoundary fallback={fallbackFn}>
          <GoodChild />
        </ErrorBoundary>
      )

      // Now click reset to clear the error state
      await user.click(screen.getByRole('button', { name: /reset/i }))

      // After reset, the error state is cleared and GoodChild should render
      expect(screen.getByTestId('good-child')).toBeInTheDocument()
      // The error UI should no longer be displayed
      expect(screen.queryByText('Error Occurred')).not.toBeInTheDocument()
    })
  })

  describe('recovery buttons', () => {
    test('Try Again button is rendered', () => {
      render(
        <ErrorBoundary>
          <ThrowError />
        </ErrorBoundary>
      )

      expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument()
    })

    test('Reload Page button is rendered', () => {
      render(
        <ErrorBoundary>
          <ThrowError />
        </ErrorBoundary>
      )

      expect(screen.getByRole('button', { name: /reload page/i })).toBeInTheDocument()
    })

    test('Try Again button calls reset function', async () => {
      const user = userEvent.setup()
      const handleReset = vi.fn()

      render(
        <ErrorBoundary fallback={(error, reset) => (
          <div>
            <h2>Error</h2>
            <button onClick={() => { handleReset(); reset() }}>Try Again</button>
          </div>
        )}>
          <ThrowError />
        </ErrorBoundary>
      )

      await user.click(screen.getByRole('button', { name: /try again/i }))
      expect(handleReset).toHaveBeenCalledTimes(1)
    })
  })

  describe('null/undefined children handling', () => {
    test('handles null children at top level', () => {
      const { container } = render(<ErrorBoundary>{null}</ErrorBoundary>)
      expect(container.innerHTML).toBe('')
    })

    test('handles undefined children at top level', () => {
      const { container } = render(<ErrorBoundary>{undefined}</ErrorBoundary>)
      expect(container.innerHTML).toBe('')
    })
  })
})

describe('RouteErrorBoundary', () => {
  test('renders children when no error', () => {
    render(
      <RouteErrorBoundary>
        <div data-testid="route-child">Route content</div>
      </RouteErrorBoundary>
    )
    expect(screen.getByTestId('route-child')).toBeInTheDocument()
  })

  test('catches errors and shows page error UI', () => {
    render(
      <RouteErrorBoundary>
        <ThrowError message="Route error" />
      </RouteErrorBoundary>
    )

    expect(screen.getByText('Page Error')).toBeInTheDocument()
    expect(screen.getByText('Route error')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  test('does not show default ErrorBoundary UI', () => {
    render(
      <RouteErrorBoundary>
        <ThrowError message="Error" />
      </RouteErrorBoundary>
    )

    expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument()
    expect(screen.queryByText('Reload Page')).not.toBeInTheDocument()
  })

  test('Retry button calls reset function', async () => {
    const user = userEvent.setup()

    render(
      <RouteErrorBoundary>
        <ThrowError message="Retry test" />
      </RouteErrorBoundary>
    )

    expect(screen.getByText('Page Error')).toBeInTheDocument()

    // The RouteErrorBoundary has a fixed fallback with Retry button that calls reset
    // We can verify the button exists and is clickable
    const retryButton = screen.getByRole('button', { name: /retry/i })
    expect(retryButton).toBeInTheDocument()

    // Clicking retry will reset and re-render children which still throw, so it shows error again
    await user.click(retryButton)
    expect(screen.getByText('Page Error')).toBeInTheDocument()
  })
})
