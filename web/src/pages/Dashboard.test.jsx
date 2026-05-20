import { render, screen, waitFor } from '@testing-library/react'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import Dashboard from './Dashboard'
import * as apiClient from '../api/client'
import { useAuthStore } from '../store'

// Mock WebSocket
class MockWebSocket {
  constructor(url) {
    this.url = url
    this.readyState = 0
    setTimeout(() => {
      this.onopen?.()
    }, 0)
  }
  close() {
    this.readyState = 3
    this.onclose?.()
  }
  send() {}
}
vi.stubGlobal('WebSocket', MockWebSocket)

// Mock dependencies
vi.mock('../hooks/useIsMobile', () => ({ useIsMobile: () => false }))
vi.mock('../contexts/PendingChangesContext', () => ({
  usePendingChanges: () => ({ totalPendingCount: 0 }),
}))

// Mock components
vi.mock('../components/StatCard', () => ({
  default: ({ label, value }) => (
    <div data-testid="stat-card">
      <span data-testid="stat-label">{label}</span>
      <span data-testid="stat-value">{value}</span>
    </div>
  ),
}))

vi.mock('../components/BlockedEventsChart', () => ({
  default: ({ logs }) => (
    <div data-testid="blocked-events-chart">
      {logs?.length || 0} logs
    </div>
  ),
}))

vi.mock('../components/RecentActivityFeed', () => ({
  default: ({ activity }) => (
    <div data-testid="recent-activity-feed">
      {activity?.length || 0} items
    </div>
  ),
}))

vi.mock('../components/QuickActions', () => ({
  default: () => <div data-testid="quick-actions">Quick Actions</div>,
}))

vi.mock('../components/TopBlockedSources', () => ({
  default: ({ sources }) => (
    <div data-testid="top-blocked-sources">
      {sources?.length || 0} sources
    </div>
  ),
}))

// Mock API client
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() },
    QUERY_KEYS: actual.QUERY_KEYS,
    REFETCH_INTERVALS: { DASHBOARD_LOGS: 60000 },
    setAuthFailureHandler: vi.fn(),
  }
})

const mockDashboardData = {
  total_peers: 10,
  online_peers: 8,
  offline_peers: 2,
  manual_peers: 3,
  total_policies: 15,
  blocked_last_hour: 25,
  blocked_last_24h: 150,
  recent_activity: [
    { timestamp: '2025-01-15T10:00:00Z', src_ip: '192.168.1.10', dst_ip: '10.0.0.1', protocol: 'TCP', action: 'DROP', hostname: 'server-1' },
    { timestamp: '2025-01-15T09:55:00Z', src_ip: '192.168.1.20', dst_ip: '10.0.0.2', protocol: 'UDP', action: 'DROP', hostname: 'server-2' },
  ],
  peer_health: [],
  top_blocked_sources: [
    { src_ip: '192.168.1.100', count: 45 },
    { src_ip: '192.168.1.101', count: 30 },
    { src_ip: '192.168.1.102', count: 20 },
  ],
}

const mockBlockedLogs = {
  logs: [
    { timestamp: '2025-01-15T10:00:00Z', action: 'DROP', src_ip: '192.168.1.10', dst_ip: '10.0.0.1', protocol: 'TCP' },
    { timestamp: '2025-01-15T09:00:00Z', action: 'DROP', src_ip: '192.168.1.20', dst_ip: '10.0.0.2', protocol: 'UDP' },
  ],
}

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

describe('Dashboard Page', () => {
  const originalState = useAuthStore.getState()

  beforeEach(() => {
    vi.clearAllMocks()
    useAuthStore.setState({ isAuthenticated: true, username: 'admin', role: 'admin' })
    apiClient.api.get.mockImplementation((path) => {
      if (path === '/dashboard') return Promise.resolve(mockDashboardData)
      if (path.includes('/logs')) return Promise.resolve(mockBlockedLogs)
      return Promise.resolve([])
    })
  })

  afterEach(() => {
    useAuthStore.setState(originalState)
    localStorage.clear()
  })

  test('renders dashboard page header', async () => {
    renderWithProviders(<Dashboard />)
    await waitFor(() => expect(screen.getByText('Dashboard')).toBeInTheDocument())
  })

  test('renders stat cards with correct values', async () => {
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByText('Total Peers')).toBeInTheDocument()
    })
    expect(screen.getByText('Online')).toBeInTheDocument()
    expect(screen.getByText('Offline')).toBeInTheDocument()
    expect(screen.getByText('Manual Peers')).toBeInTheDocument()
    expect(screen.getByText('Active Policies')).toBeInTheDocument()
    expect(screen.getByText('Pending Changes')).toBeInTheDocument()
    expect(screen.getByText('Blocked (1h)')).toBeInTheDocument()
    expect(screen.getByText('Blocked (24h)')).toBeInTheDocument()
  })

  test('displays correct stat values from API', async () => {
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByText('Total Peers')).toBeInTheDocument()
    })
    // Values should match mock data
    expect(screen.getByText('10')).toBeInTheDocument() // total_peers
    expect(screen.getByText('8')).toBeInTheDocument()  // online_peers
    expect(screen.getByText('2')).toBeInTheDocument()  // offline_peers
    expect(screen.getByText('3')).toBeInTheDocument()  // manual_peers
    expect(screen.getByText('15')).toBeInTheDocument() // total_policies
    expect(screen.getByText('25')).toBeInTheDocument() // blocked_last_hour
    expect(screen.getByText('150')).toBeInTheDocument() // blocked_last_24h
  })

  test('shows loading skeleton while fetching', async () => {
    apiClient.api.get.mockImplementation(() => new Promise(() => {}))
    renderWithProviders(<Dashboard />)
    // TableSkeleton renders
    expect(screen.queryByText('Dashboard')).not.toBeInTheDocument()
  })

  test('renders blocked events chart', async () => {
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByText('Blocked Events (Last 24 Hours)')).toBeInTheDocument()
    })
    expect(screen.getByTestId('blocked-events-chart')).toBeInTheDocument()
  })

  test('renders recent activity feed', async () => {
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByTestId('recent-activity-feed')).toBeInTheDocument()
    })
  })

  test('renders quick actions component', async () => {
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByTestId('quick-actions')).toBeInTheDocument()
    })
  })

  test('renders top blocked sources', async () => {
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByTestId('top-blocked-sources')).toBeInTheDocument()
    })
  })

  test('shows live connection status', async () => {
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByText('Dashboard')).toBeInTheDocument()
    })
    // Connection status should be shown (either "Live" or "Reconnecting...")
    const statusText = screen.getByText(/Live|Reconnecting/)
    expect(statusText).toBeInTheDocument()
  })

  test('uses default values when API returns null', async () => {
    apiClient.api.get.mockResolvedValue(null)
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByText('Dashboard')).toBeInTheDocument()
    })
    // Should show default zeros (multiple stat cards each show 0)
    const zeros = screen.getAllByText('0')
    expect(zeros.length).toBeGreaterThanOrEqual(1)
  })

  test('shows pending changes count from context', async () => {
    vi.mock('../contexts/PendingChangesContext', () => ({
      usePendingChanges: () => ({ totalPendingCount: 5 }),
    }))
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByText('Pending Changes')).toBeInTheDocument()
    })
    expect(screen.getByText('5')).toBeInTheDocument()
  })

  test('renders with empty recent activity', async () => {
    apiClient.api.get.mockImplementation((path) => {
      if (path === '/dashboard') return Promise.resolve({ ...mockDashboardData, recent_activity: [] })
      if (path.includes('/logs')) return Promise.resolve(mockBlockedLogs)
      return Promise.resolve([])
    })
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByTestId('recent-activity-feed')).toBeInTheDocument()
    })
    // Should show 0 items
    expect(screen.getByText('0 items')).toBeInTheDocument()
  })

  test('renders with empty top blocked sources', async () => {
    apiClient.api.get.mockImplementation((path) => {
      if (path === '/dashboard') return Promise.resolve({ ...mockDashboardData, top_blocked_sources: [] })
      if (path.includes('/logs')) return Promise.resolve(mockBlockedLogs)
      return Promise.resolve([])
    })
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByTestId('top-blocked-sources')).toBeInTheDocument()
    })
    // Should show 0 sources
    expect(screen.getByText('0 sources')).toBeInTheDocument()
  })
})