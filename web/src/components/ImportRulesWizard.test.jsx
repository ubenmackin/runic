import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock the API client
vi.mock('../api/client', () => ({
  initiateImport: vi.fn(),
  getImportSession: vi.fn(),
  getImportRules: vi.fn(),
  getImportGroups: vi.fn(),
  getImportPeers: vi.fn(),
  getImportServices: vi.fn(),
  getImportSkipped: vi.fn(),
  updateImportRule: vi.fn(),
  applyImport: vi.fn(),
  cancelImport: vi.fn(),
  QUERY_KEYS: {
    peers: () => ['peers'],
    groups: () => ['groups'],
    services: () => ['services'],
    policies: () => ['policies'],
    pendingChanges: () => ['pendingChanges'],
  },
}))

import ImportRulesWizard from './ImportRulesWizard'
import * as api from '../api/client'

// Mock ToastContext
const mockShowToast = vi.fn()
vi.mock('../hooks/ToastContext', () => ({
  useToastContext: () => ({ showToast: mockShowToast }),
}))

// Mock useFocusTrap
vi.mock('../hooks/useFocusTrap', () => ({
  useFocusTrap: vi.fn(),
}))

// Mock StepIndicator
vi.mock('./StepIndicator', () => ({
  default: ({ steps, currentStep }) => (
    <div data-testid="step-indicator">
      {steps.map((s) => (
        <span key={s.key} data-active={s.key === currentStep ? 'true' : 'false'}>
          {s.label}
        </span>
      ))}
    </div>
  ),
}))

// Mock child components
vi.mock('./ImportRulesWizard/FetchStep', () => ({
  default: ({ fetchStatus }) => (
    <div data-testid="fetch-step" data-status={fetchStatus}>
      Fetch Step: {fetchStatus}
    </div>
  ),
}))

vi.mock('./ImportRulesWizard/ReviewContent', () => ({
  default: ({
    loading,
    importableRules,
    approveAll,
    rejectAll,
    skippedCount,
  }) => (
    <div data-testid="review-content">
      {loading ? (
        <div>Loading review...</div>
      ) : (
        <>
          <div>Importable rules: {importableRules.length}</div>
          <div>Skipped: {skippedCount}</div>
          <button onClick={approveAll}>Approve All</button>
          <button onClick={rejectAll}>Reject All</button>
        </>
      )}
    </div>
  ),
}))

vi.mock('./ImportRulesWizard/ApplyStep', () => ({
  default: ({ approvedRulesCount }) => (
    <div data-testid="apply-step">
      <div>Rules: {approvedRulesCount}</div>
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

const mockPeer = { id: 1, hostname: 'test-peer', ip_address: '192.168.1.1' }

describe('ImportRulesWizard', () => {
  let wrapper
  let user

  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers({ shouldAdvanceTime: true })
    wrapper = createWrapper()
    user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
  })

  afterEach(() => {
    vi.useRealTimers()
    // Portal cleanup handled by React
  })

  // Helper to advance through the fetch step's polling
  async function advanceFetchStep() {
    // initiateImport is called on mount
    await vi.advanceTimersByTimeAsync(100)
    // First poll timer is set for 2000ms
    await vi.advanceTimersByTimeAsync(2100)
    // Status check happens and if parsed, auto-advance after 800ms
    await vi.advanceTimersByTimeAsync(900)
  }

  describe('rendering and portal', () => {
    test('renders modal in portal to document.body', () => {
      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      const overlay = document.querySelector('.fixed.inset-0')
      expect(overlay).toBeInTheDocument()
    })

    test('renders modal title with peer hostname', () => {
      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      expect(
        screen.getByText('Import Pre-Runic Rules — test-peer')
      ).toBeInTheDocument()
    })

    test('renders step indicators', () => {
      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      expect(screen.getByText('Fetch')).toBeInTheDocument()
      expect(screen.getByText('Review')).toBeInTheDocument()
      expect(screen.getByText('Apply')).toBeInTheDocument()
    })
  })

  describe('step 1: fetch', () => {
    test('starts at fetch step', () => {
      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      expect(screen.getByTestId('fetch-step')).toBeInTheDocument()
    })

    test('initiates import on mount', async () => {
      api.initiateImport.mockResolvedValue({ session_id: 'sess-123' })

      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      // Let the effect run
      await vi.advanceTimersByTimeAsync(100)

      expect(api.initiateImport).toHaveBeenCalledWith(1)
    })

    test('shows Cancel button on fetch step', () => {
      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      const cancelButtons = screen.getAllByText('Cancel')
      expect(cancelButtons.length).toBeGreaterThan(0)
    })

    test('calls onClose when Cancel is clicked', async () => {
      const handleClose = vi.fn()

      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={handleClose}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      const cancelButtons = screen.getAllByText('Cancel')
      await user.click(cancelButtons[0])

      expect(handleClose).toHaveBeenCalled()
    })

    test('calls cancelImport when closing during fetch', async () => {
      api.initiateImport.mockResolvedValue({ session_id: 'sess-123' })
      const handleClose = vi.fn()

      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={handleClose}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      await vi.advanceTimersByTimeAsync(100)

      const cancelButtons = screen.getAllByText('Cancel')
      await user.click(cancelButtons[0])

      expect(api.cancelImport).toHaveBeenCalledWith('sess-123')
      expect(handleClose).toHaveBeenCalled()
    })
  })

  describe('step 2: review', () => {
    test('transitions to review step when session is parsed', async () => {
      api.initiateImport.mockResolvedValue({ session_id: 'sess-123' })

      // The first poll will get "parsed" status
      api.getImportSession.mockResolvedValue({ status: 'parsed' })

      // Review data mocks
      api.getImportRules.mockResolvedValue([])
      api.getImportGroups.mockResolvedValue([])
      api.getImportPeers.mockResolvedValue([])
      api.getImportServices.mockResolvedValue([])
      api.getImportSkipped.mockResolvedValue([])

      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      // Advance through: initiateImport, first poll timer, parsed auto-advance
      await advanceFetchStep()

      await waitFor(() => {
        expect(screen.getByTestId('review-content')).toBeInTheDocument()
      })
    })

    test('transitions to review and shows importable rules', async () => {
      api.initiateImport.mockResolvedValue({ session_id: 'sess-123' })

      api.getImportSession.mockResolvedValue({ status: 'parsed' })

      api.getImportRules.mockResolvedValue([
        { id: 1, status: 'pending', chain: 'INPUT', action: 'ACCEPT', source_name: 'src', target_name: 'dst', service_name: 'svc', direction: 'forward', raw_rule: '-A INPUT ...' },
        { id: 2, status: 'skipped', chain: 'FORWARD', action: 'DROP' },
      ])
      api.getImportGroups.mockResolvedValue([])
      api.getImportPeers.mockResolvedValue([])
      api.getImportServices.mockResolvedValue([])
      api.getImportSkipped.mockResolvedValue([{ id: 99, raw_rule: 'skip-rule', skip_reason: 'unsupported' }])

      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      await advanceFetchStep()

      await waitFor(() => {
        expect(
          screen.getByText(/Importable rules: 1/)
        ).toBeInTheDocument()
      })

      expect(screen.getByText(/Skipped: 1/)).toBeInTheDocument()
    })
  })

  describe('review actions', () => {
    test('calls updateImportRule when Approve All is clicked', async () => {
      api.initiateImport.mockResolvedValue({ session_id: 'sess-123' })
      api.getImportSession.mockResolvedValue({ status: 'parsed' })
      api.getImportRules.mockResolvedValue([
        { id: 1, status: 'pending', chain: 'INPUT', action: 'ACCEPT' },
      ])
      api.getImportGroups.mockResolvedValue([])
      api.getImportPeers.mockResolvedValue([])
      api.getImportServices.mockResolvedValue([])
      api.getImportSkipped.mockResolvedValue([])
      api.updateImportRule.mockResolvedValue({})

      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      await advanceFetchStep()
      await vi.advanceTimersByTimeAsync(100)

      await waitFor(() => {
        expect(screen.getByText('Approve All')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Approve All'))

      await vi.advanceTimersByTimeAsync(100)

      expect(api.updateImportRule).toHaveBeenCalledWith('sess-123', 1, { status: 'approved' })
    })

    test('calls updateImportRule when Reject All is clicked', async () => {
      api.initiateImport.mockResolvedValue({ session_id: 'sess-123' })
      api.getImportSession.mockResolvedValue({ status: 'parsed' })
      api.getImportRules.mockResolvedValue([
        { id: 1, status: 'pending', chain: 'INPUT', action: 'ACCEPT' },
      ])
      api.getImportGroups.mockResolvedValue([])
      api.getImportPeers.mockResolvedValue([])
      api.getImportServices.mockResolvedValue([])
      api.getImportSkipped.mockResolvedValue([])
      api.updateImportRule.mockResolvedValue({})

      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      await advanceFetchStep()
      await vi.advanceTimersByTimeAsync(100)

      await waitFor(() => {
        expect(screen.getByText('Reject All')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Reject All'))

      await vi.advanceTimersByTimeAsync(100)

      expect(api.updateImportRule).toHaveBeenCalledWith('sess-123', 1, { status: 'resolved' })
    })
  })

  describe('step 3: apply', () => {
    test('navigates to apply step when Next is clicked', async () => {
      api.initiateImport.mockResolvedValue({ session_id: 'sess-123' })
      api.getImportSession.mockResolvedValue({ status: 'parsed' })
      api.getImportRules.mockResolvedValue([])
      api.getImportGroups.mockResolvedValue([])
      api.getImportPeers.mockResolvedValue([])
      api.getImportServices.mockResolvedValue([])
      api.getImportSkipped.mockResolvedValue([])

      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      await advanceFetchStep()
      await vi.advanceTimersByTimeAsync(100)

      await waitFor(() => {
        expect(screen.getByTestId('review-content')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Next'))
      await vi.advanceTimersByTimeAsync(100)

      expect(screen.getByTestId('apply-step')).toBeInTheDocument()
    })

    test('calls applyImport when Apply Import is clicked', async () => {
      api.initiateImport.mockResolvedValue({ session_id: 'sess-123' })
      api.getImportSession.mockResolvedValue({ status: 'parsed' })
      api.getImportRules.mockResolvedValue([
        { id: 1, status: 'approved', chain: 'INPUT', action: 'ACCEPT' },
      ])
      api.getImportGroups.mockResolvedValue([])
      api.getImportPeers.mockResolvedValue([])
      api.getImportServices.mockResolvedValue([])
      api.getImportSkipped.mockResolvedValue([])
      api.applyImport.mockResolvedValue({})

      const handleClose = vi.fn()
      const handleSuccess = vi.fn()

      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={handleClose}
          onSuccess={handleSuccess}
        />,
        { wrapper }
      )

      await advanceFetchStep()
      await vi.advanceTimersByTimeAsync(100)

      await waitFor(() => {
        expect(screen.getByTestId('review-content')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Next'))
      await vi.advanceTimersByTimeAsync(100)
      expect(screen.getByTestId('apply-step')).toBeInTheDocument()

      await user.click(screen.getByText('Apply Import'))
      await vi.advanceTimersByTimeAsync(100)

      await waitFor(() => {
        expect(api.applyImport).toHaveBeenCalledWith('sess-123')
        expect(handleSuccess).toHaveBeenCalled()
        expect(handleClose).toHaveBeenCalled()
      })
    })

    test('shows applying state while submitting', async () => {
      api.initiateImport.mockResolvedValue({ session_id: 'sess-123' })
      api.getImportSession.mockResolvedValue({ status: 'parsed' })
      api.getImportRules.mockResolvedValue([
        { id: 1, status: 'approved', chain: 'INPUT', action: 'ACCEPT' },
      ])
      api.getImportGroups.mockResolvedValue([])
      api.getImportPeers.mockResolvedValue([])
      api.getImportServices.mockResolvedValue([])
      api.getImportSkipped.mockResolvedValue([])
      api.applyImport.mockImplementation(
        () => new Promise((resolve) => setTimeout(() => resolve({}), 100))
      )

      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      await advanceFetchStep()
      await vi.advanceTimersByTimeAsync(100)

      await waitFor(() => {
        expect(screen.getByTestId('review-content')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Next'))
      await vi.advanceTimersByTimeAsync(100)
      await user.click(screen.getByText('Apply Import'))
      await vi.advanceTimersByTimeAsync(50)

      expect(screen.getByText('Applying...')).toBeInTheDocument()
    })
  })

  describe('error handling', () => {
    test('shows error when initiateImport fails', async () => {
      api.initiateImport.mockRejectedValue(new Error('Connection failed'))

      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      await vi.advanceTimersByTimeAsync(100)

      await waitFor(() => {
        expect(screen.getByText('Connection failed')).toBeInTheDocument()
      })
    })

    test('shows 409 error for active import session', async () => {
      const err = new Error('This peer already has an active import session')
      err.status = 409
      api.initiateImport.mockRejectedValue(err)

      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      await vi.advanceTimersByTimeAsync(100)

      await waitFor(() => {
        expect(
          screen.getByText('This peer already has an active import session')
        ).toBeInTheDocument()
      })
    })

    test('shows error for 400 status', async () => {
      const err = new Error('Import not allowed for this peer')
      err.status = 400
      api.initiateImport.mockRejectedValue(err)

      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      await vi.advanceTimersByTimeAsync(100)

      await waitFor(() => {
        expect(
          screen.getByText('Import not allowed for this peer')
        ).toBeInTheDocument()
      })
    })
  })

  describe('back navigation', () => {
    test('can go back from review to fetch step', async () => {
      api.initiateImport.mockResolvedValue({ session_id: 'sess-123' })
      api.getImportSession.mockResolvedValue({ status: 'parsed' })
      api.getImportRules.mockResolvedValue([])
      api.getImportGroups.mockResolvedValue([])
      api.getImportPeers.mockResolvedValue([])
      api.getImportServices.mockResolvedValue([])
      api.getImportSkipped.mockResolvedValue([])

      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      await advanceFetchStep()
      await vi.advanceTimersByTimeAsync(100)

      await waitFor(() => {
        expect(screen.getByTestId('review-content')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Back'))
      await vi.advanceTimersByTimeAsync(100)

      expect(screen.getByTestId('fetch-step')).toBeInTheDocument()
    })

    test('can go back from apply to review step', async () => {
      api.initiateImport.mockResolvedValue({ session_id: 'sess-123' })
      api.getImportSession.mockResolvedValue({ status: 'parsed' })
      api.getImportRules.mockResolvedValue([])
      api.getImportGroups.mockResolvedValue([])
      api.getImportPeers.mockResolvedValue([])
      api.getImportServices.mockResolvedValue([])
      api.getImportSkipped.mockResolvedValue([])

      render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      await advanceFetchStep()
      await vi.advanceTimersByTimeAsync(100)

      await waitFor(() => {
        expect(screen.getByTestId('review-content')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Next'))
      await vi.advanceTimersByTimeAsync(100)
      expect(screen.getByTestId('apply-step')).toBeInTheDocument()

      await user.click(screen.getByText('Back'))
      await vi.advanceTimersByTimeAsync(100)
      expect(screen.getByTestId('review-content')).toBeInTheDocument()
    })
  })

  describe('modal cleanup', () => {
    test('modal is removed from DOM when unmounted', () => {
      api.initiateImport.mockResolvedValue({ session_id: 'sess-123' })

      const { unmount } = render(
        <ImportRulesWizard
          peer={mockPeer}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper }
      )

      expect(
        document.querySelector('.fixed.inset-0')
      ).toBeInTheDocument()

      unmount()

      expect(
        document.querySelector('.fixed.inset-0')
      ).not.toBeInTheDocument()
    })
  })
})
