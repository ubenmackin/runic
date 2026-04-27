import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Peers from './Peers'
import * as apiClient from '../api/client'
import { useAuthStore } from '../store'

// Mock useIsMobile hook to return false for desktop view
vi.mock('../hooks/useIsMobile', () => ({
  useIsMobile: () => false,
}))

// Mock the API client
vi.mock('../api/client', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
  QUERY_KEYS: {
    peers: () => ['peers'],
    peerIps: (id) => ['peers', id, 'ips'],
    groups: () => ['groups'],
    services: () => ['services'],
    policies: () => ['policies'],
    info: () => ['info'],
  },
  getPeerIPs: vi.fn(() => Promise.resolve([])),
  addPeerIP: vi.fn(() => Promise.resolve()),
  deletePeerIP: vi.fn(() => Promise.resolve()),
  setAuthFailureHandler: vi.fn(),
}))

// Mock useFocusTrap hook
vi.mock('../hooks/useFocusTrap', () => ({
  useFocusTrap: vi.fn(),
}))

// Mock useSSE hook
vi.mock('../hooks/useSSE', () => ({
  useSSE: vi.fn(),
}))

// Mock react-router-dom
vi.mock('react-router-dom', () => ({
  useLocation: () => ({ state: null }),
}))

// Mock toast context
const mockShowToast = vi.fn()
vi.mock('../hooks/ToastContext', () => ({
  useToastContext: () => mockShowToast,
}))

// Mock SearchableSelect component
vi.mock('../components/SearchableSelect', () => ({
  default: ({ options, value, onChange, placeholder }) => (
    <select
      value={value || ''}
      onChange={(e) => onChange?.(e.target.value)}
      aria-label="Searchable Select"
      data-testid="searchable-select"
    >
      <option value="">{placeholder}</option>
      {options?.map((opt) => (
        <option key={opt.value} value={opt.value}>
          {opt.label}
        </option>
      ))}
    </select>
  ),
}))

// Helper to create wrapper with query client
function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
      },
      mutations: {
        retry: false,
      },
    },
  })

  return function Wrapper({ children }) {
    return (
      <QueryClientProvider client={queryClient}>
        {children}
      </QueryClientProvider>
    )
  }
}

// Helper to render with all providers
function renderWithProviders(ui, options = {}) {
  const wrapper = createWrapper()
  return render(ui, { wrapper, ...options })
}

// Helper to get the desktop table body for scoped queries
function getDesktopTableBody() {
  return document.querySelector('table tbody')
}

// Helper to get the desktop table for scoped queries
function getDesktopTable() {
  return document.querySelector('table')
}

// Mock peers data
const mockPeers = [
  { id: 1, hostname: 'server-alpha', ip_address: '192.168.1.10', status: 'online', agent_version: '1.0.0', os_type: 'ubuntu', last_heartbeat: new Date().toISOString(), groups: 'web,servers', sync_status: 'synced' },
  { id: 2, hostname: 'server-beta', ip_address: '192.168.1.20', status: 'offline', agent_version: '1.1.0', os_type: 'ubuntu', last_heartbeat: new Date(Date.now() - 3600000).toISOString(), groups: 'db', sync_status: 'pending' },
  { id: 3, hostname: 'server-gamma', ip_address: '192.168.1.30', status: 'online', agent_version: '1.2.0', os_type: 'debian', last_heartbeat: new Date().toISOString(), groups: 'web', sync_status: 'synced' },
]

describe('Peers Page', () => {
  const originalState = useAuthStore.getState()

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    // Reset auth store to default state
    useAuthStore.setState({
      isAuthenticated: true,
      username: 'testuser',
      role: 'admin',
    })
    // Default API mocks
    apiClient.api.get.mockImplementation((path) => {
      if (path === '/peers') return Promise.resolve(mockPeers)
      if (path === '/policies/special-targets') return Promise.resolve([])
      return Promise.resolve([])
    })
  })

  afterEach(() => {
    useAuthStore.setState(originalState)
    localStorage.clear()
  })

  describe('Sortable Columns', () => {
    test('Status column header is clickable', async () => {
      renderWithProviders(<Peers />)

      // Wait for table to load using scoped query to desktop table
      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      // Find the Status column header button
      const statusHeader = screen.getByRole('button', { name: /Status/ })
      expect(statusHeader).toBeInTheDocument()
    })

    test('Agent column header is clickable', async () => {
      renderWithProviders(<Peers />)

      // Wait for table to load using scoped query
      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      // Find the Agent column header button - be more specific
      const agentHeaders = screen.getAllByRole('button', { name: /Agent/ })
      // Should find at least one Agent header
      expect(agentHeaders.length).toBeGreaterThan(0)
    })

    test('SortIndicator is rendered for sortable columns', async () => {
      renderWithProviders(<Peers />)

      // Wait for table to load using scoped query
      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      // Check that sortable column headers exist - be more specific with exact text
      const hostnameHeader = screen.getByRole('button', { name: /^Hostname/ })
      const statusHeader = screen.getByRole('button', { name: /^Status/ })

      expect(hostnameHeader).toBeInTheDocument()
      expect(statusHeader).toBeInTheDocument()

      // Agent header - there might be multiple, just check one exists
      const agentHeaders = screen.getAllByRole('button', { name: /Agent/ })
      expect(agentHeaders.length).toBeGreaterThan(0)
    })

    test('Hostname column is sortable (default sort)', async () => {
      renderWithProviders(<Peers />)

      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      // The default sort is hostname, so check that the table is rendered
      const rows = screen.getAllByRole('row')
      expect(rows.length).toBeGreaterThan(1) // Header + at least one data row
    })
  })

  describe('Table Rendering', () => {
    test('renders peer table with data', async () => {
      renderWithProviders(<Peers />)

      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      const tbody = getDesktopTableBody()
      expect(within(tbody).getByText('server-beta')).toBeInTheDocument()
      expect(within(tbody).getByText('server-gamma')).toBeInTheDocument()
    })

    test('shows online/offline status indicators', async () => {
      renderWithProviders(<Peers />)

      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      // Online status dot (green)
      const onlineDots = document.querySelectorAll('.bg-green-500')
      expect(onlineDots.length).toBeGreaterThan(0)
    })
  })

  describe('Filter Controls', () => {
    test('status filter buttons are rendered', async () => {
      const user = userEvent.setup()
      renderWithProviders(<Peers />)

      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      // Expand the Search & Filters panel first
      const disclosureButton = screen.getByRole('button', { name: /Search & Filters/ })
      await user.click(disclosureButton)

      // Wait for the panel to expand
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'All' })).toBeInTheDocument()
      })

      // Check that filter buttons exist
      expect(screen.getByRole('button', { name: 'All' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Online' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Offline' })).toBeInTheDocument()
    })

    test('clicking status filter updates visible peers', async () => {
      const user = userEvent.setup()
      renderWithProviders(<Peers />)

      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      // Expand the Search & Filters panel first
      const disclosureButton = screen.getByRole('button', { name: /Search & Filters/ })
      await user.click(disclosureButton)

      // Wait for the panel to expand
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Offline' })).toBeInTheDocument()
      })

      // Click Offline filter
      await user.click(screen.getByRole('button', { name: 'Offline' }))

      // Only offline peer should be visible - use scoped query
      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(within(tbody).getByText('server-beta')).toBeInTheDocument()
        // Online peers should be filtered out
        expect(within(tbody).queryByText('server-alpha')).not.toBeInTheDocument()
      })
    })
  })

  describe('Search Functionality', () => {
    test('search input filters peers', async () => {
      const user = userEvent.setup()
      renderWithProviders(<Peers />)

      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      // Expand the Search & Filters panel first
      const disclosureButton = screen.getByRole('button', { name: /Search & Filters/ })
      await user.click(disclosureButton)

      // Wait for the panel to expand and search input to be visible
      await waitFor(() => {
        expect(screen.getByPlaceholderText(/Search peers/)).toBeInTheDocument()
      })

      const searchInput = screen.getByPlaceholderText(/Search peers/)
      await user.type(searchInput, 'alpha')

      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
        expect(within(tbody).queryByText('server-beta')).not.toBeInTheDocument()
      })
    })
  })

  describe('Sort Order Changes', () => {
    // Mock peers data with different status values for sorting tests
    const sortingMockPeers = [
      { id: 1, hostname: 'server-alpha', ip_address: '192.168.1.10', status: 'offline', agent_version: '1.0.0', os_type: 'ubuntu', last_heartbeat: new Date().toISOString(), groups: 'web', sync_status: 'synced', pending_changes_count: 0 },
      { id: 2, hostname: 'server-beta', ip_address: '192.168.1.20', status: 'online', agent_version: '1.2.0', os_type: 'ubuntu', last_heartbeat: new Date().toISOString(), groups: 'db', sync_status: 'synced', pending_changes_count: 0 },
      { id: 3, hostname: 'server-gamma', ip_address: '192.168.1.30', status: 'pending', agent_version: '0.9.0', os_type: 'debian', last_heartbeat: new Date().toISOString(), groups: 'web', sync_status: 'synced', pending_changes_count: 0 },
      { id: 4, hostname: 'server-delta', ip_address: '192.168.1.40', status: 'online', agent_version: '1.1.0', os_type: 'ubuntu', last_heartbeat: new Date().toISOString(), groups: 'cache', sync_status: 'synced', pending_changes_count: 0 },
    ]

    test('clicking Status column header changes sort order indicator', async () => {
      // Set up mock with sorting-specific data
      apiClient.api.get.mockImplementation((path) => {
        if (path === '/peers') return Promise.resolve(sortingMockPeers)
        if (path === '/policies/special-targets') return Promise.resolve([])
        return Promise.resolve([])
      })

      const user = userEvent.setup()
      renderWithProviders(<Peers />)

      // Wait for table to load using scoped query
      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      // Find the Status column header button
      const statusHeader = screen.getByRole('button', { name: /^Status/ })
      expect(statusHeader).toBeInTheDocument()

      // Get initial sort indicator state - should show neutral indicator (ArrowUpDown)
      const container = statusHeader.closest('th')
      const neutralIcon = container.querySelector('.text-gray-400')
      expect(neutralIcon).toBeInTheDocument()

      // Click the Status header to sort
      await user.click(statusHeader)

      // After click, should show active sort indicator (ArrowUp for asc)
      await waitFor(() => {
        const activeIcon = container.querySelector('.text-runic-500')
        expect(activeIcon).toBeInTheDocument()
      })
    })

    test('clicking Agent column header changes sort order indicator', async () => {
      // Set up mock with sorting-specific data
      apiClient.api.get.mockImplementation((path) => {
        if (path === '/peers') return Promise.resolve(sortingMockPeers)
        if (path === '/policies/special-targets') return Promise.resolve([])
        return Promise.resolve([])
      })

      const user = userEvent.setup()
      renderWithProviders(<Peers />)

      // Wait for table to load using scoped query
      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      // Find the Agent column header button in the table header
      // Use within to scope search to the table
      const table = getDesktopTable()
      const agentHeader = table.querySelector('th:nth-child(7) button')
      expect(agentHeader).toBeInTheDocument()

      // Get container for sort indicator
      const container = agentHeader.closest('th')
      const neutralIcon = container.querySelector('.text-gray-400')
      expect(neutralIcon).toBeInTheDocument()

      // Click the Agent header to sort
      await user.click(agentHeader)

      // After click, should show active sort indicator (ArrowUp for asc)
      await waitFor(() => {
        const activeIcon = container.querySelector('.text-runic-500')
        expect(activeIcon).toBeInTheDocument()
      })
    })

    test('clicking sort header toggles sort direction', async () => {
      // Set up mock with sorting-specific data
      apiClient.api.get.mockImplementation((path) => {
        if (path === '/peers') return Promise.resolve(sortingMockPeers)
        if (path === '/policies/special-targets') return Promise.resolve([])
        return Promise.resolve([])
      })

      const user = userEvent.setup()
      renderWithProviders(<Peers />)

      // Wait for table to load using scoped query
      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      const statusHeader = screen.getByRole('button', { name: /^Status/ })
      const container = statusHeader.closest('th')

      // First click - sort asc
      await user.click(statusHeader)
      await waitFor(() => {
        const ascIcon = container.querySelector('.text-runic-500')
        expect(ascIcon).toBeInTheDocument()
      })

      // Second click - sort desc (toggle direction)
      await user.click(statusHeader)
      await waitFor(() => {
        // ArrowDown icon should still have the active class
        const descIcon = container.querySelector('.text-runic-500')
        expect(descIcon).toBeInTheDocument()
      })
    })

    test('data is reordered when sorted by status ascending', async () => {
      // Set up mock with sorting-specific data
      apiClient.api.get.mockImplementation((path) => {
        if (path === '/peers') return Promise.resolve(sortingMockPeers)
        if (path === '/policies/special-targets') return Promise.resolve([])
        return Promise.resolve([])
      })

      const user = userEvent.setup()
      renderWithProviders(<Peers />)

      // Wait for table to load using scoped query
      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      // Get the initial order by checking row positions
      const getRowOrder = () => {
        const rows = document.querySelectorAll('tbody tr')
        return Array.from(rows).map(row => row.querySelector('td')?.textContent?.trim())
      }

      // Click Status header to sort ascending (offline < online < pending alphabetically)
      const statusHeader = screen.getByRole('button', { name: /^Status/ })
      await user.click(statusHeader)

      await waitFor(() => {
        const order = getRowOrder()
        // When sorted by status ascending, 'offline' should come before 'online' and 'pending'
        // server-alpha (offline), then server-beta/server-delta (online), then server-gamma (pending)
        expect(order).toBeDefined()
        expect(order.length).toBe(4)
        // First item should be server-alpha (offline status)
        expect(order[0]).toContain('server-alpha')
      })
    })

    test('data is reordered when sorted by agent version ascending', async () => {
      // Set up mock with sorting-specific data
      apiClient.api.get.mockImplementation((path) => {
        if (path === '/peers') return Promise.resolve(sortingMockPeers)
        if (path === '/policies/special-targets') return Promise.resolve([])
        return Promise.resolve([])
      })

      const user = userEvent.setup()
      renderWithProviders(<Peers />)

      // Wait for table to load using scoped query
      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      // Find the Agent column header button in the table header
      const table = getDesktopTable()
      const agentHeader = table.querySelector('th:nth-child(7) button')

      // Click Agent header to sort ascending
      await user.click(agentHeader)

      await waitFor(() => {
        // Get all rows and check order
        const rows = document.querySelectorAll('tbody tr')
        const hostnames = Array.from(rows).map(row => row.querySelector('td')?.textContent?.trim())

        // Agent versions: server-gamma (0.9.0), server-alpha (1.0.0), server-delta (1.1.0), server-beta (1.2.0)
        // When sorted ascending by agent_version string comparison:
        // '0.9.0' < '1.0.0' < '1.1.0' < '1.2.0'
        expect(hostnames[0]).toContain('server-gamma') // 0.9.0
        expect(hostnames[1]).toContain('server-alpha') // 1.0.0
        expect(hostnames[2]).toContain('server-delta') // 1.1.0
        expect(hostnames[3]).toContain('server-beta') // 1.2.0
      })
    })

    test('data is reordered correctly when toggling from asc to desc', async () => {
      // Set up mock with sorting-specific data
      apiClient.api.get.mockImplementation((path) => {
        if (path === '/peers') return Promise.resolve(sortingMockPeers)
        if (path === '/policies/special-targets') return Promise.resolve([])
        return Promise.resolve([])
      })

      const user = userEvent.setup()
      renderWithProviders(<Peers />)

      // Wait for table to load using scoped query
      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      // Find the Agent column header button in the table header
      const table = getDesktopTable()
      const agentHeader = table.querySelector('th:nth-child(7) button')

      // Click once for ascending
      await user.click(agentHeader)

      await waitFor(() => {
        const rows = document.querySelectorAll('tbody tr')
        const hostnames = Array.from(rows).map(row => row.querySelector('td')?.textContent?.trim())
        expect(hostnames[0]).toContain('server-gamma') // 0.9.0 - lowest version first
      })

      // Click again for descending
      await user.click(agentHeader)

      await waitFor(() => {
        const rows = document.querySelectorAll('tbody tr')
        const hostnames = Array.from(rows).map(row => row.querySelector('td')?.textContent?.trim())
        // Descending order: 1.2.0, 1.1.0, 1.0.0, 0.9.0
        expect(hostnames[0]).toContain('server-beta') // 1.2.0 - highest version first
        expect(hostnames[3]).toContain('server-gamma') // 0.9.0 - lowest version last
      })
    })

    test('sort state is maintained when switching between columns', async () => {
      // Set up mock with sorting-specific data
      apiClient.api.get.mockImplementation((path) => {
        if (path === '/peers') return Promise.resolve(sortingMockPeers)
        if (path === '/policies/special-targets') return Promise.resolve([])
        return Promise.resolve([])
      })

      const user = userEvent.setup()
      renderWithProviders(<Peers />)

      // Wait for table to load using scoped query
      await waitFor(() => {
        const tbody = getDesktopTableBody()
        expect(tbody).toBeInTheDocument()
        expect(within(tbody).getByText('server-alpha')).toBeInTheDocument()
      })

      const statusHeader = screen.getByRole('button', { name: /^Status/ })
      const table = getDesktopTable()
      const agentHeader = table.querySelector('th:nth-child(7) button')

      // Sort by Status ascending
      await user.click(statusHeader)
      await waitFor(() => {
        const container = statusHeader.closest('th')
        expect(container.querySelector('.text-runic-500')).toBeInTheDocument()
      })

      // Switch to Agent - should start with ascending
      await user.click(agentHeader)
      await waitFor(() => {
        const agentContainer = agentHeader.closest('th')
        expect(agentContainer.querySelector('.text-runic-500')).toBeInTheDocument()
        // Status should no longer be active
        const statusContainer = statusHeader.closest('th')
        expect(statusContainer.querySelector('.text-gray-400')).toBeInTheDocument()
      })
    })
  })
})
