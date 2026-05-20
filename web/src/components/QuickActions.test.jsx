import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

import QuickActions from './QuickActions'

// Mock react-router-dom
const mockNavigate = vi.fn()
vi.mock('react-router-dom', () => ({
  useNavigate: () => mockNavigate,
}))

// Mock API client
vi.mock('../api/client', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
  },
  QUERY_KEYS: {
    peers: () => ['peers'],
  },
}))

import { api } from '../api/client'

// Mock ToastContext
const mockShowToast = vi.fn()
vi.mock('../hooks/ToastContext', () => ({
  useToastContext: () => mockShowToast,
}))

// Mock ConfirmModal
vi.mock('./ConfirmModal', () => ({
  default: ({ title, message, onConfirm, onCancel }) => (
    <div data-testid="confirm-modal">
      <div>{title}</div>
      <div>{message}</div>
      <button onClick={onConfirm} data-testid="confirm-yes">
        Confirm
      </button>
      <button onClick={onCancel} data-testid="confirm-no">
        Cancel
      </button>
    </div>
  ),
}))

// Mock PushJobModal
vi.mock('./PushJobModal', () => ({
  default: ({ jobId, onClose }) => (
    <div data-testid="push-job-modal">
      <div>Job ID: {jobId}</div>
      <button onClick={onClose} data-testid="push-job-close">
        Close
      </button>
    </div>
  ),
}))

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
    },
  })
  return function Wrapper({ children }) {
    return (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    )
  }
}

describe('QuickActions', () => {
  let wrapper

  beforeEach(() => {
    vi.clearAllMocks()
    wrapper = createWrapper()
  })

  describe('rendering', () => {
    test('renders title', () => {
      api.get.mockResolvedValue([])

      render(<QuickActions />, { wrapper })

      expect(screen.getByText('Quick Actions')).toBeInTheDocument()
    })

    test('renders all action buttons', async () => {
      api.get.mockResolvedValue([])

      render(<QuickActions />, { wrapper })

      await waitFor(() => {
        expect(
          screen.getByRole('button', { name: 'Push Rules to All' })
        ).toBeInTheDocument()
        expect(
          screen.getByRole('button', { name: 'Add Peer' })
        ).toBeInTheDocument()
        expect(
          screen.getByRole('button', { name: 'Create Policy' })
        ).toBeInTheDocument()
      })
    })
  })

  describe('push rules to all', () => {
    test('shows loading state on button while peers are loading', () => {
      api.get.mockImplementation(() => new Promise(() => {}))

      render(<QuickActions />, { wrapper })

      expect(screen.getByText('Loading...')).toBeInTheDocument()
    })

    test('shows confirm modal when Push Rules is clicked', async () => {
      const user = userEvent.setup()
      api.get.mockResolvedValue([{ id: 1, hostname: 'peer-1' }])

      render(<QuickActions />, { wrapper })

      await waitFor(() => {
        expect(
          screen.getByRole('button', { name: 'Push Rules to All' })
        ).not.toBeDisabled()
      })

      await user.click(
        screen.getByRole('button', { name: 'Push Rules to All' })
      )

      expect(
        screen.getByText('Push Rules to All Peers')
      ).toBeInTheDocument()
    })

    test('calls push API when confirmed', async () => {
      const user = userEvent.setup()
      api.get.mockResolvedValue([{ id: 1, hostname: 'peer-1' }])
      api.post.mockResolvedValue({ job_id: 'job-123' })

      render(<QuickActions />, { wrapper })

      await waitFor(() => {
        expect(
          screen.getByRole('button', { name: 'Push Rules to All' })
        ).not.toBeDisabled()
      })

      await user.click(
        screen.getByRole('button', { name: 'Push Rules to All' })
      )

      await user.click(screen.getByTestId('confirm-yes'))

      await waitFor(() => {
        expect(api.post).toHaveBeenCalledWith(
          '/pending-changes/push-all'
        )
      })
    })

    test('shows PushJobModal when push succeeds with job_id', async () => {
      const user = userEvent.setup()
      api.get.mockResolvedValue([{ id: 1, hostname: 'peer-1' }])
      api.post.mockResolvedValue({ job_id: 'job-123' })

      render(<QuickActions />, { wrapper })

      await waitFor(() => {
        expect(
          screen.getByRole('button', { name: 'Push Rules to All' })
        ).not.toBeDisabled()
      })

      await user.click(
        screen.getByRole('button', { name: 'Push Rules to All' })
      )

      await user.click(screen.getByTestId('confirm-yes'))

      await waitFor(() => {
        expect(screen.getByTestId('push-job-modal')).toBeInTheDocument()
        expect(screen.getByText('Job ID: job-123')).toBeInTheDocument()
      })
    })

    test('shows info toast when no job_id returned', async () => {
      const user = userEvent.setup()
      api.get.mockResolvedValue([{ id: 1, hostname: 'peer-1' }])
      api.post.mockResolvedValue({}) // No job_id

      render(<QuickActions />, { wrapper })

      await waitFor(() => {
        expect(
          screen.getByRole('button', { name: 'Push Rules to All' })
        ).not.toBeDisabled()
      })

      await user.click(
        screen.getByRole('button', { name: 'Push Rules to All' })
      )

      await user.click(screen.getByTestId('confirm-yes'))

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith(
          'No peers to push to',
          'info'
        )
      })
    })

    test('shows error toast when push fails', async () => {
      const user = userEvent.setup()
      api.get.mockResolvedValue([{ id: 1, hostname: 'peer-1' }])
      api.post.mockRejectedValue({ message: 'Push failed' })

      render(<QuickActions />, { wrapper })

      await waitFor(() => {
        expect(
          screen.getByRole('button', { name: 'Push Rules to All' })
        ).not.toBeDisabled()
      })

      await user.click(
        screen.getByRole('button', { name: 'Push Rules to All' })
      )

      await user.click(screen.getByTestId('confirm-yes'))

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith(
          'Failed to start push: Push failed',
          'error'
        )
      })
    })
  })

  describe('navigation', () => {
    test('navigates to peers page with openAddModal state when Add Peer is clicked', async () => {
      const user = userEvent.setup()
      api.get.mockResolvedValue([])

      render(<QuickActions />, { wrapper })

      await waitFor(() => {
        expect(
          screen.getByRole('button', { name: 'Add Peer' })
        ).toBeInTheDocument()
      })

      await user.click(screen.getByRole('button', { name: 'Add Peer' }))

      expect(mockNavigate).toHaveBeenCalledWith('/peers', {
        state: { openAddModal: true },
      })
    })

    test('navigates to policies page with openAddModal state when Create Policy is clicked', async () => {
      const user = userEvent.setup()
      api.get.mockResolvedValue([])

      render(<QuickActions />, { wrapper })

      await waitFor(() => {
        expect(
          screen.getByRole('button', { name: 'Create Policy' })
        ).toBeInTheDocument()
      })

      await user.click(
        screen.getByRole('button', { name: 'Create Policy' })
      )

      expect(mockNavigate).toHaveBeenCalledWith('/policies', {
        state: { openAddModal: true },
      })
    })
  })

  describe('push job modal cleanup', () => {
    test('invalidates peers query when PushJobModal is closed', async () => {
      const user = userEvent.setup()
      api.get.mockResolvedValue([{ id: 1, hostname: 'peer-1' }])
      api.post.mockResolvedValue({ job_id: 'job-123' })

      render(<QuickActions />, { wrapper })

      await waitFor(() => {
        expect(
          screen.getByRole('button', { name: 'Push Rules to All' })
        ).not.toBeDisabled()
      })

      await user.click(
        screen.getByRole('button', { name: 'Push Rules to All' })
      )
      await user.click(screen.getByTestId('confirm-yes'))

      await waitFor(() => {
        expect(screen.getByTestId('push-job-modal')).toBeInTheDocument()
      })

      await user.click(screen.getByTestId('push-job-close'))

      await waitFor(() => {
        expect(
          screen.queryByTestId('push-job-modal')
        ).not.toBeInTheDocument()
      })
    })
  })
})
