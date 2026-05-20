import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import ApiErrorDisplay, { ApiErrorInline, ApiErrorCard, NetworkStatus } from './ApiErrorDisplay'

describe('ApiErrorDisplay', () => {
  describe('rendering', () => {
    test('renders error message from error object', () => {
      render(<ApiErrorDisplay error={{ message: 'Something went wrong' }} />)
      expect(screen.getByText('Something went wrong')).toBeInTheDocument()
    })

    test('renders error message from string', () => {
      render(<ApiErrorDisplay error="Simple error string" />)
      expect(screen.getByText('Simple error string')).toBeInTheDocument()
    })

    test('renders default title for unknown errors', () => {
      render(<ApiErrorDisplay error={{ message: 'Unknown error' }} />)
      expect(screen.getByText('Error')).toBeInTheDocument()
    })

    test('renders icon by default', () => {
      render(<ApiErrorDisplay error={{ message: 'Error with icon' }} />)
      const svgs = document.querySelectorAll('svg')
      expect(svgs.length).toBeGreaterThan(0)
    })

    test('hides icon when showIcon is false', () => {
      render(<ApiErrorDisplay error={{ message: 'Error without icon' }} showIcon={false} />)
      const svgs = document.querySelectorAll('svg')
      expect(svgs.length).toBe(0)
    })
  })

  describe('error types', () => {
    test('renders network error type with connection icon', () => {
      render(<ApiErrorDisplay error={{ message: 'Network issue', type: 'network' }} />)
      expect(screen.getByText('Connection Error')).toBeInTheDocument()
      expect(screen.getByText('Network issue')).toBeInTheDocument()
    })

    test('renders auth error type', () => {
      render(<ApiErrorDisplay error={{ message: 'Auth failed', type: 'auth' }} />)
      expect(screen.getByText('Authentication Required')).toBeInTheDocument()
      expect(screen.getByText('Auth failed')).toBeInTheDocument()
    })

    test('renders not_found error type', () => {
      render(<ApiErrorDisplay error={{ message: 'Resource not found', type: 'not_found' }} />)
      expect(screen.getByText('Not Found')).toBeInTheDocument()
      expect(screen.getByText('Resource not found')).toBeInTheDocument()
    })

    test('renders server error type', () => {
      render(<ApiErrorDisplay error={{ message: 'Server error', type: 'server' }} />)
      expect(screen.getByText('Server Error')).toBeInTheDocument()
      expect(screen.getByText('Server error')).toBeInTheDocument()
    })

    test('renders validation error type', () => {
      render(<ApiErrorDisplay error={{ message: 'Invalid data', type: 'validation' }} />)
      expect(screen.getByText('Error')).toBeInTheDocument()
      expect(screen.getByText('Invalid data')).toBeInTheDocument()
    })

    test('renders permission error type', () => {
      render(<ApiErrorDisplay error={{ message: 'No permission', type: 'permission' }} />)
      expect(screen.getByText('Error')).toBeInTheDocument()
      expect(screen.getByText('No permission')).toBeInTheDocument()
    })
  })

  describe('retry button', () => {
    test('renders retry button when onRetry is provided and error is recoverable', () => {
      render(
        <ApiErrorDisplay
          error={{ message: 'Error', recoverable: true }}
          onRetry={() => {}}
        />
      )
      expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument()
    })

    test('does not render retry button when onRetry is not provided', () => {
      render(<ApiErrorDisplay error={{ message: 'Error', recoverable: true }} />)
      expect(screen.queryByRole('button')).not.toBeInTheDocument()
    })

    test('does not render retry button when error is not recoverable', () => {
      render(
        <ApiErrorDisplay
          error={{ message: 'Error', recoverable: false }}
          onRetry={() => {}}
        />
      )
      expect(screen.queryByRole('button')).not.toBeInTheDocument()
    })

    test('calls onRetry when retry button is clicked', async () => {
      const user = userEvent.setup()
      const handleRetry = vi.fn()

      render(
        <ApiErrorDisplay
          error={{ message: 'Error', recoverable: true }}
          onRetry={handleRetry}
        />
      )

      await user.click(screen.getByRole('button', { name: /try again/i }))
      expect(handleRetry).toHaveBeenCalledTimes(1)
    })
  })

  describe('suggested action', () => {
    test('renders suggested action when provided', () => {
      render(
        <ApiErrorDisplay
          error={{ message: 'Error', suggestedAction: 'Please try again later.' }}
        />
      )
      expect(screen.getByText('Please try again later.')).toBeInTheDocument()
    })

    test('does not render suggested action when not provided', () => {
      render(<ApiErrorDisplay error={{ message: 'Error' }} />)
      // Should not have the paragraph with suggested action
    })
  })

  describe('auth type login link', () => {
    test('renders login link for auth errors', () => {
      render(<ApiErrorDisplay error={{ message: 'Auth error', type: 'auth' }} />)
      expect(screen.getByRole('link', { name: /log in/i })).toHaveAttribute('href', '/login')
    })
  })

  describe('compact mode', () => {
    test('renders in compact mode', () => {
      render(
        <ApiErrorDisplay
          error={{ message: 'Compact error' }}
          compact={true}
          showIcon={false}
        />
      )
      expect(screen.getByText('Compact error')).toBeInTheDocument()
    })

    test('shows alert icon in compact mode by default', () => {
      render(
        <ApiErrorDisplay
          error={{ message: 'Compact error' }}
          compact={true}
        />
      )
      const svgs = document.querySelectorAll('svg')
      expect(svgs.length).toBeGreaterThan(0)
    })

    test('compact mode has retry button', () => {
      render(
        <ApiErrorDisplay
          error={{ message: 'Error', recoverable: true }}
          compact={true}
          onRetry={() => {}}
        />
      )
      expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
    })

    test('compact mode does not show retry when recoverable is false', () => {
      render(
        <ApiErrorDisplay
          error={{ message: 'Error', recoverable: false }}
          compact={true}
          onRetry={() => {}}
        />
      )
      expect(screen.queryByRole('button')).not.toBeInTheDocument()
    })
  })

  describe('custom className', () => {
    test('applies custom className to wrapper', () => {
      const { container } = render(
        <ApiErrorDisplay error={{ message: 'Error' }} className="my-custom-class" />
      )
      const wrapper = container.firstChild
      expect(wrapper.className).toContain('my-custom-class')
    })
  })

  describe('null/undefined handling', () => {
    test('returns null when error is null', () => {
      const { container } = render(<ApiErrorDisplay error={null} />)
      expect(container.innerHTML).toBe('')
    })

    test('returns null when error is undefined', () => {
      const { container } = render(<ApiErrorDisplay error={undefined} />)
      expect(container.innerHTML).toBe('')
    })

    test('handles error object without message', () => {
      render(<ApiErrorDisplay error={{}} />)
      expect(screen.getByText('An error occurred')).toBeInTheDocument()
    })

    test('handles error with only type', () => {
      render(<ApiErrorDisplay error={{ type: 'network' }} />)
      expect(screen.getByText('An error occurred')).toBeInTheDocument()
    })
  })
})

describe('ApiErrorInline', () => {
  describe('rendering', () => {
    test('renders error message', () => {
      render(<ApiErrorInline message="Inline error message" />)
      expect(screen.getByText('Inline error message')).toBeInTheDocument()
    })

    test('renders retry button when onRetry is provided', () => {
      render(<ApiErrorInline message="Error" onRetry={() => {}} />)
      expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
    })

    test('does not show icon', () => {
      render(<ApiErrorInline message="Error" />)
      // Should not crash
    })
  })
})

describe('ApiErrorCard', () => {
  describe('rendering', () => {
    test('renders with title and error', () => {
      render(
        <ApiErrorCard
          title="Dashboard Error"
          error={{ message: 'Failed to load dashboard data' }}
        />
      )
      expect(screen.getByText('Dashboard Error')).toBeInTheDocument()
      expect(screen.getByText('Failed to load dashboard data')).toBeInTheDocument()
    })

    test('renders without title', () => {
      render(<ApiErrorCard error={{ message: 'Error without title' }} />)
      expect(screen.getByText('Error without title')).toBeInTheDocument()
    })

    test('renders with string error', () => {
      render(<ApiErrorCard title="Error" error="String error message" />)
      expect(screen.getByText('String error message')).toBeInTheDocument()
    })

    test('renders with retry button', () => {
      render(
        <ApiErrorCard
          title="Error"
          error={{ message: 'Retryable error' }}
          onRetry={() => {}}
        />
      )
      expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument()
    })
  })

  describe('null/undefined handling', () => {
    test('returns null when error is null', () => {
      const { container } = render(<ApiErrorCard error={null} />)
      expect(container.innerHTML).toBe('')
    })

    test('returns null when error is undefined', () => {
      const { container } = render(<ApiErrorCard error={undefined} />)
      expect(container.innerHTML).toBe('')
    })
  })
})

describe('NetworkStatus', () => {
  describe('connected state', () => {
    test('shows connected status', () => {
      render(<NetworkStatus connected={true} />)
      expect(screen.getByText('Connected')).toBeInTheDocument()
    })

    test('does not show reconnect button when connected', () => {
      render(<NetworkStatus connected={true} onRetry={() => {}} />)
      expect(screen.queryByRole('button')).not.toBeInTheDocument()
    })

    test('connected has green styling', () => {
      const { container } = render(<NetworkStatus connected={true} />)
      const wrapper = container.firstChild
      expect(wrapper.className).toContain('bg-green-100')
      expect(wrapper.className).toContain('text-green-700')
    })
  })

  describe('disconnected state', () => {
    test('shows disconnected status', () => {
      render(<NetworkStatus connected={false} />)
      expect(screen.getByText('Disconnected')).toBeInTheDocument()
    })

    test('shows reconnect button when onRetry is provided', () => {
      render(<NetworkStatus connected={false} onRetry={() => {}} />)
      expect(screen.getByRole('button', { name: /reconnect/i })).toBeInTheDocument()
    })

    test('does not show reconnect button when onRetry is not provided', () => {
      render(<NetworkStatus connected={false} />)
      expect(screen.queryByRole('button')).not.toBeInTheDocument()
    })

    test('disconnected has red styling', () => {
      const { container } = render(<NetworkStatus connected={false} />)
      const wrapper = container.firstChild
      expect(wrapper.className).toContain('bg-red-100')
      expect(wrapper.className).toContain('text-red-700')
    })

    test('calls onRetry when reconnect button is clicked', async () => {
      const user = userEvent.setup()
      const handleRetry = vi.fn()

      render(<NetworkStatus connected={false} onRetry={handleRetry} />)

      await user.click(screen.getByRole('button', { name: /reconnect/i }))
      expect(handleRetry).toHaveBeenCalledTimes(1)
    })
  })
})
