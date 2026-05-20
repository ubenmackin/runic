import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock API client
vi.mock('../api/client', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
  },
  QUERY_KEYS: {
    alertRules: () => ['alertRules'],
    peers: () => ['peers'],
  },
  getAlertRules: vi.fn(),
  updateAlertRule: vi.fn(),
}))

import AlertSettings from './AlertSettings'
import * as api from '../api/client'

// Mock ToastContext
const mockShowToast = vi.fn()
vi.mock('../hooks/ToastContext', () => ({
  useToastContext: () => ({ showToast: mockShowToast }),
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

const sampleAlertRules = [
  { id: 1, alert_type: 'bundle_deployed', enabled: true, threshold_value: 1, threshold_window_minutes: 5, throttle_minutes: 5, peer_override_hostname: '' },
  { id: 2, alert_type: 'bundle_failed', enabled: false, threshold_value: 1, threshold_window_minutes: 5, throttle_minutes: 30, peer_override_hostname: null },
  { id: 3, alert_type: 'peer_offline', enabled: true, threshold_value: 3, threshold_window_minutes: 15, throttle_minutes: 15, peer_override_hostname: 'peer-1' },
  { id: 4, alert_type: 'blocked_spike', enabled: true, threshold_value: 1000, threshold_window_minutes: 5, throttle_minutes: 5, peer_override_hostname: '' },
]

const samplePeers = [
  { id: 1, hostname: 'peer-1' },
  { id: 2, hostname: 'peer-2' },
]

describe('AlertSettings', () => {
  let wrapper

  beforeEach(() => {
    vi.clearAllMocks()
    wrapper = createWrapper()
  })

  describe('loading state', () => {
    test('shows loading spinner when alert rules are loading', () => {
      api.getAlertRules.mockReturnValue(new Promise(() => {}))

      render(<AlertSettings />, { wrapper })

      expect(screen.getByText('Loading alert rules...')).toBeInTheDocument()
    })
  })

  describe('error state', () => {
    test('shows error message when query fails', async () => {
      api.getAlertRules.mockRejectedValue(new Error('Network error'))

      render(<AlertSettings />, { wrapper })

      await waitFor(() => {
        expect(
          screen.getByText(/Failed to load alert rules/)
        ).toBeInTheDocument()
      })
    })
  })

  describe('rendering', () => {
    test('shows header when showHeader is true', async () => {
      api.getAlertRules.mockResolvedValue([])
      api.api.get.mockResolvedValue([])

      render(<AlertSettings showHeader={true} />, { wrapper })

      await waitFor(() => {
        expect(screen.getByText('Alert Rules')).toBeInTheDocument()
      })
    })

    test('hides header when showHeader is false', async () => {
      api.getAlertRules.mockResolvedValue([])
      api.api.get.mockResolvedValue([])

      render(<AlertSettings showHeader={false} />, { wrapper })

      await waitFor(() => {
        expect(screen.queryByText('Alert Rules')).not.toBeInTheDocument()
      })
    })

    test('renders all alert types in table', async () => {
      api.getAlertRules.mockResolvedValue(sampleAlertRules)
      api.api.get.mockResolvedValue(samplePeers)

      render(<AlertSettings />, { wrapper })

      await waitFor(() => {
        expect(screen.getByText('Bundle Deployed')).toBeInTheDocument()
        expect(screen.getByText('Bundle Failed')).toBeInTheDocument()
        expect(screen.getByText('Peer Offline')).toBeInTheDocument()
        expect(screen.getByText('Peer Online')).toBeInTheDocument()
        expect(screen.getByText('Blocked Traffic Spike')).toBeInTheDocument()
        expect(screen.getByText('New Peer Registered')).toBeInTheDocument()
      })
    })

    test('renders table headers', async () => {
      api.getAlertRules.mockResolvedValue(sampleAlertRules)
      api.api.get.mockResolvedValue(samplePeers)

      render(<AlertSettings />, { wrapper })

      await waitFor(() => {
        expect(screen.getByText('Alert Type')).toBeInTheDocument()
        expect(screen.getByText('Enabled')).toBeInTheDocument()
        expect(screen.getByText('Threshold')).toBeInTheDocument()
        expect(screen.getByText('Window (min)')).toBeInTheDocument()
        expect(screen.getByText('Throttle (min)')).toBeInTheDocument()
        expect(screen.getByText('Peer Override')).toBeInTheDocument()
      })
    })

    test('renders toggle switches for each alert type', async () => {
      api.getAlertRules.mockResolvedValue(sampleAlertRules)
      api.api.get.mockResolvedValue(samplePeers)

      render(<AlertSettings />, { wrapper })

      await waitFor(() => {
        const switches = screen.getAllByRole('switch')
        expect(switches.length).toBe(6)
      })
    })
  })

  describe('toggle interaction', () => {
    test('calls updateAlertRule when toggle is changed', async () => {
      api.getAlertRules.mockResolvedValue(sampleAlertRules)
      api.api.get.mockResolvedValue(samplePeers)
      api.updateAlertRule.mockResolvedValue({})

      const user = userEvent.setup()

      render(<AlertSettings />, { wrapper })

      await waitFor(() => {
        expect(screen.getAllByRole('switch').length).toBe(6)
      })

      const switches = screen.getAllByRole('switch')
      await user.click(switches[1]) // Toggle bundle_failed from false to true

      await waitFor(() => {
        expect(api.updateAlertRule).toHaveBeenCalled()
      })
    })
  })

  describe('threshold input', () => {
    test('renders threshold input for each alert type', async () => {
      api.getAlertRules.mockResolvedValue(sampleAlertRules)
      api.api.get.mockResolvedValue(samplePeers)

      render(<AlertSettings />, { wrapper })

      await waitFor(() => {
        const numberInputs = screen.getAllByRole('spinbutton')
        expect(numberInputs.length).toBe(6)
      })
    })

    test('updates threshold on blur', async () => {
      api.getAlertRules.mockResolvedValue(sampleAlertRules)
      api.api.get.mockResolvedValue(samplePeers)
      api.updateAlertRule.mockResolvedValue({})

      const user = userEvent.setup()

      render(<AlertSettings />, { wrapper })

      await waitFor(() => {
        expect(screen.getAllByRole('spinbutton').length).toBe(6)
      })

      const firstInput = screen.getAllByRole('spinbutton')[0]
      await user.clear(firstInput)
      await user.type(firstInput, '50')
      await user.tab() // blur

      await waitFor(() => {
        expect(api.updateAlertRule).toHaveBeenCalled()
      })
    })
  })

  describe('peer override dropdown', () => {
    test('shows All Peers option and peer list', async () => {
      api.getAlertRules.mockResolvedValue(sampleAlertRules)
      api.api.get.mockResolvedValue(samplePeers)

      render(<AlertSettings />, { wrapper })

      await waitFor(() => {
        const selects = screen.getAllByRole('combobox')
        // 6 rows × 3 selects each (window, throttle, peer_override) = 18
        expect(selects.length).toBe(18)
        // "All Peers" should appear in Peer Override selects (one per row)
        expect(screen.getAllByText('All Peers').length).toBe(6)
        // Peer hostnames should be in dropdowns
        expect(screen.getAllByText('peer-1').length).toBeGreaterThan(0)
        expect(screen.getAllByText('peer-2').length).toBeGreaterThan(0)
      })
    })
  })

  describe('configuration notes', () => {
    test('renders info note section', async () => {
      api.getAlertRules.mockResolvedValue(sampleAlertRules)
      api.api.get.mockResolvedValue(samplePeers)

      render(<AlertSettings />, { wrapper })

      await waitFor(() => {
        expect(screen.getByText('Configuration Notes:')).toBeInTheDocument()
        expect(screen.getByText(/Threshold:/)).toBeInTheDocument()
        expect(screen.getByText(/Window:/)).toBeInTheDocument()
        expect(screen.getByText(/Throttle:/)).toBeInTheDocument()
        expect(screen.getByText(/Peer Override:/)).toBeInTheDocument()
      })
    })
  })

  describe('error handling on mutation', () => {
    test('shows toast when update fails', async () => {
      api.getAlertRules.mockResolvedValue(sampleAlertRules)
      api.api.get.mockResolvedValue(samplePeers)
      api.updateAlertRule.mockRejectedValue(new Error('Update failed'))

      const user = userEvent.setup()

      render(<AlertSettings />, { wrapper })

      await waitFor(() => {
        expect(screen.getAllByRole('switch').length).toBe(6)
      })

      const switches = screen.getAllByRole('switch')
      await user.click(switches[0])

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith('Update failed', 'error')
      })
    })
  })
})
