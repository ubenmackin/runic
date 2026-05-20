import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import Alerts from './Alerts'
import * as apiClient from '../api/client'
import { useAuthStore } from '../store'

// Mock dependencies
vi.mock('../hooks/useIsMobile', () => ({ useIsMobile: () => false }))
vi.mock('../hooks/useFocusTrap', () => ({ useFocusTrap: vi.fn() }))

// Mock toast
const mockShowToast = vi.fn()
vi.mock('../hooks/ToastContext', () => ({ useToastContext: () => mockShowToast }))

// Mock API client
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() },
    QUERY_KEYS: actual.QUERY_KEYS,
    deleteAlert: vi.fn(),
    clearAllAlerts: vi.fn(),
    setAuthFailureHandler: vi.fn(),
  }
})

const mockAlerts = [
  {
    id: 1,
    alert_type: 'bundle_failed',
    severity: 'critical',
    status: 'sent',
    subject: 'Bundle deployment failed on peer-01',
    message: 'Failed to deploy bundle #42 on peer-01',
    peer_hostname: 'peer-01',
    peer_id: 'p1',
    created_at: '2025-01-15T10:30:00Z',
    sent_at: '2025-01-15T10:31:00Z',
    metadata: { bundle_id: 42 },
  },
  {
    id: 2,
    alert_type: 'peer_offline',
    severity: 'warning',
    status: 'pending',
    subject: 'Peer peer-02 went offline',
    message: 'Peer peer-02 has been offline for 5 minutes',
    peer_hostname: 'peer-02',
    peer_id: 'p2',
    created_at: '2025-01-15T09:00:00Z',
    sent_at: null,
    metadata: null,
  },
]

function createWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
  return function Wrapper({ children }) {
    return (
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          {children}
        </BrowserRouter>
      </QueryClientProvider>
    )
  }
}

function renderWithProviders(ui) {
  return render(ui, { wrapper: createWrapper() })
}

describe('Alerts Page', () => {
  const originalState = useAuthStore.getState()

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    useAuthStore.setState({ isAuthenticated: true, username: 'admin', role: 'admin' })
    apiClient.api.get.mockImplementation((path) => {
      if (path.startsWith('/alerts')) {
        return Promise.resolve({ alerts: mockAlerts, total: 2 })
      }
      return Promise.resolve([])
    })
  })

  afterEach(() => {
    useAuthStore.setState(originalState)
    localStorage.clear()
  })

  test('renders page header', async () => {
    renderWithProviders(<Alerts />)
    await waitFor(() => expect(screen.getByText('Alerts')).toBeInTheDocument())
    expect(screen.getByText('View alert history and notifications')).toBeInTheDocument()
  })

  test('shows alert rows in table', async () => {
    renderWithProviders(<Alerts />)
    await waitFor(() => {
      expect(screen.getAllByText('[BUNDLE_FAILED]').length).toBeGreaterThan(0)
    })
    expect(screen.getAllByText('[PEER_OFFLINE]').length).toBeGreaterThan(0)
  })

  test('shows peer hostnames in alert rows', async () => {
    renderWithProviders(<Alerts />)
    await waitFor(() => {
      expect(screen.getAllByText('peer-01').length).toBeGreaterThan(0)
      expect(screen.getAllByText('peer-02').length).toBeGreaterThan(0)
    })
  })

  test('shows status tags for alerts', async () => {
    renderWithProviders(<Alerts />)
    await waitFor(() => {
      expect(screen.getAllByText('[SENT]').length).toBeGreaterThan(0)
      expect(screen.getAllByText('[PENDING]').length).toBeGreaterThan(0)
    })
  })

  test('shows Clear All Alerts button when alerts exist', async () => {
    renderWithProviders(<Alerts />)
    // The "Clear All Alerts" text appears both in header button and confirmation modal text
    await waitFor(() => {
      const buttons = screen.getAllByRole('button')
      const clearAllBtn = buttons.find(btn => btn.textContent.includes('Clear All Alerts'))
      expect(clearAllBtn).toBeTruthy()
    })
  })

  test('shows access denied for non-admin users', async () => {
    useAuthStore.setState({ role: 'viewer' })
    renderWithProviders(<Alerts />)
    await waitFor(() => {
      expect(screen.getByText('Access Denied')).toBeInTheDocument()
    })
    expect(screen.getByText('You need administrator access to view the Alerts page.')).toBeInTheDocument()
  })

  test('shows loading skeleton while fetching', async () => {
    apiClient.api.get.mockImplementation(() => new Promise(() => {}))
    renderWithProviders(<Alerts />)
    expect(screen.queryByText('[BUNDLE_FAILED]')).not.toBeInTheDocument()
  })

  test('shows empty state when no alerts match filters', async () => {
    apiClient.api.get.mockResolvedValue({ alerts: [], total: 0 })
    renderWithProviders(<Alerts />)
    await waitFor(() => {
      expect(screen.getAllByText('No alerts').length).toBeGreaterThan(0)
    })
  })

  test('shows Search & Filters panel', async () => {
    renderWithProviders(<Alerts />)
    await waitFor(() => {
      expect(screen.getByText('Filters')).toBeInTheDocument()
    })
  })

  test('shows expand/collapse buttons for alert rows', async () => {
    renderWithProviders(<Alerts />)
    await waitFor(() => {
      expect(screen.getAllByText('[BUNDLE_FAILED]').length).toBeGreaterThan(0)
    })
    const expandButtons = screen.getAllByRole('button', { name: /Expand details|Collapse details/i })
    expect(expandButtons.length).toBeGreaterThan(0)
  })

  test('opens delete confirmation modal from expanded row', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Alerts />)
    await waitFor(() => {
      expect(screen.getAllByText('[BUNDLE_FAILED]').length).toBeGreaterThan(0)
    })

    // Expand the first alert row
    const expandButtons = screen.getAllByRole('button', { name: /Expand details/i })
    await user.click(expandButtons[0])

    await waitFor(() => {
      // Find the "Delete Alert" button within the expanded row details
      const deleteButtons = screen.getAllByRole('button').filter(b => b.textContent.trim() === 'Delete Alert')
      expect(deleteButtons.length).toBeGreaterThan(0)
    })
  })

  test('calls deleteAlert when confirming deletion', async () => {
    apiClient.deleteAlert.mockResolvedValue({})
    const user = userEvent.setup()

    renderWithProviders(<Alerts />)
    await waitFor(() => {
      expect(screen.getAllByText('[BUNDLE_FAILED]').length).toBeGreaterThan(0)
    })

    // Expand first alert and click Delete Alert
    const expandButtons = screen.getAllByRole('button', { name: /Expand details/i })
    await user.click(expandButtons[0])

    const deleteAlertBtn = await screen.findByText('Delete Alert')
    await user.click(deleteAlertBtn)

    // Now the modal should show
    await waitFor(() => {
      expect(screen.getByText('Delete Alert?')).toBeInTheDocument()
    })

    // Click Delete in modal (the confirm button)
    const confirmBtn = screen.getAllByRole('button').find(b => b.textContent.trim() === 'Delete')
    await user.click(confirmBtn)

    await waitFor(() => {
      expect(apiClient.deleteAlert).toHaveBeenCalledWith(1, expect.any(Object))
    })
  })

  test('calls clearAllAlerts when confirming clear all', async () => {
    apiClient.clearAllAlerts.mockResolvedValue({})
    const user = userEvent.setup()

    renderWithProviders(<Alerts />)
    await waitFor(() => {
      expect(screen.getAllByText('[BUNDLE_FAILED]').length).toBeGreaterThan(0)
    })

    // Click the Clear All Alerts button in the header
    const headerBtn = screen.getAllByRole('button').find(b => b.textContent.includes('Clear All Alerts'))
    await user.click(headerBtn)

    // Now the modal should show
    await waitFor(() => {
      expect(screen.getByText('Clear All Alerts?')).toBeInTheDocument()
    })

    // Click "Clear All Alerts" confirm button in modal
    const confirmBtns = screen.getAllByRole('button').filter(b => b.textContent.trim() === 'Clear All Alerts')
    // The confirm button is the last one (in the modal)
    await user.click(confirmBtns[confirmBtns.length - 1])

    await waitFor(() => {
      expect(apiClient.clearAllAlerts).toHaveBeenCalled()
    })
  })

  test('shows error toast on delete failure', async () => {
    apiClient.deleteAlert.mockRejectedValue(new Error('Delete failed'))
    const user = userEvent.setup()

    renderWithProviders(<Alerts />)
    await waitFor(() => {
      expect(screen.getAllByText('[BUNDLE_FAILED]').length).toBeGreaterThan(0)
    })

    // Expand and delete
    const expandButtons = screen.getAllByRole('button', { name: /Expand details/i })
    await user.click(expandButtons[0])

    const deleteAlertBtn = await screen.findByText('Delete Alert')
    await user.click(deleteAlertBtn)

    await waitFor(() => {
      expect(screen.getByText('Delete Alert?')).toBeInTheDocument()
    })

    const confirmBtn = screen.getAllByRole('button').find(b => b.textContent.trim() === 'Delete')
    await user.click(confirmBtn)

    await waitFor(() => {
      expect(mockShowToast).toHaveBeenCalledWith('Delete failed', 'error')
    })
  })
})