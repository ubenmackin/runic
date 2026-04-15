import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Logs from './Logs'
import * as apiClient from '../api/client'

// Mock the API client
vi.mock('../api/client', () => ({
  api: {
    get: vi.fn(),
  },
  QUERY_KEYS: {
    logs: () => ['logs'],
    peers: () => ['peers'],
  },
}))

// Mock SearchableSelect component - render as a simple select
vi.mock('../components/SearchableSelect', () => ({
  default: ({ options, value, onChange, placeholder }) => (
    <select
      value={value || ''}
      onChange={(e) => onChange?.(e.target.value)}
      aria-label="Peer select"
      data-testid="peer-select"
    >
      <option value="">{placeholder || 'All peers'}</option>
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

// Mock logs data
const mockLogs = [
  { id: 1, timestamp: '2024-01-15T10:30:00Z', action: 'BLOCK', src_ip: '192.168.1.100', dst_port: 22, peer_hostname: 'server-alpha' },
  { id: 2, timestamp: '2024-01-15T10:29:00Z', action: 'ACCEPT', src_ip: '10.0.0.5', dst_port: 443, peer_hostname: 'server-beta' },
]

const mockPeers = [
  { id: 1, hostname: 'server-alpha' },
  { id: 2, hostname: 'server-beta' },
]

describe('Logs Page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    // Default API mocks
    apiClient.api.get.mockImplementation((path) => {
      if (path.startsWith('/logs')) return Promise.resolve({ logs: mockLogs, total: 2 })
      if (path === '/peers') return Promise.resolve(mockPeers)
      return Promise.resolve([])
    })
  })

  afterEach(() => {
    localStorage.clear()
  })

  describe('Filter Disclosure State Persistence', () => {
    test('filter disclosure reads from localStorage on mount (collapsed)', async () => {
      // Set localStorage to collapsed state BEFORE rendering
      localStorage.setItem('logs-filters-expanded', 'false')

      renderWithProviders(<Logs />)

      await waitFor(() => {
        expect(screen.getByText('Logs')).toBeInTheDocument()
      })

    // Should show the filter button with aria-expanded=false
    const filterButton = screen.getByRole('button', { name: /Filters/ })
      expect(filterButton).toBeInTheDocument()
      expect(filterButton).toHaveAttribute('aria-expanded', 'false')

      // Verify no Source IP input is visible (since collapsed)
      expect(screen.queryByPlaceholderText('e.g. 192.168.1')).not.toBeInTheDocument()
    })

    test('filter inputs become visible after clicking expand', async () => {
      // Set localStorage to collapsed state BEFORE rendering so we start collapsed
      localStorage.setItem('logs-filters-expanded', 'false')

      const user = userEvent.setup()
      renderWithProviders(<Logs />)

      await waitFor(() => {
        expect(screen.getByText('Logs')).toBeInTheDocument()
      })

      // Verify inputs are hidden initially (collapsed state)
      expect(screen.queryByPlaceholderText('e.g. 192.168.1')).not.toBeInTheDocument()

    const filtersButton = screen.getByRole('button', { name: /Filters/ })
    await user.click(filtersButton)

    // After clicking, filter inputs should be visible
      await waitFor(() => {
        expect(screen.getByPlaceholderText('e.g. 192.168.1')).toBeInTheDocument()
      })
      expect(screen.getByPlaceholderText('e.g. 443')).toBeInTheDocument()
    })

    test('filter expanded state shows Active badge when filters have values', async () => {
      // Set localStorage to collapsed state BEFORE rendering
      localStorage.setItem('logs-filters-expanded', 'false')

      const user = userEvent.setup()
      renderWithProviders(<Logs />)

      await waitFor(() => {
        expect(screen.getByText('Logs')).toBeInTheDocument()
      })

    // Expand filters
    const filtersButton = screen.getByRole('button', { name: /Filters/ })
    await user.click(filtersButton)

      // Wait for filter inputs to be visible
      await waitFor(() => {
        expect(screen.getByPlaceholderText('e.g. 192.168.1')).toBeInTheDocument()
      })

      // Type in source IP filter
      const srcIpInput = screen.getByPlaceholderText('e.g. 192.168.1')
      await user.type(srcIpInput, '192.168')

      // Active badge should appear
      await waitFor(() => {
        expect(screen.getByText('Active')).toBeInTheDocument()
      })
    })
  })

  describe('Mode Toggle', () => {
    test('defaults to historical mode', async () => {
      renderWithProviders(<Logs />)

      await waitFor(() => {
        expect(screen.getByText('Logs')).toBeInTheDocument()
      })

      // Historical button should be active
      const historicalButton = screen.getByRole('button', { name: 'Historical' })
      expect(historicalButton).toHaveClass('bg-purple-active')
    })
  })

  describe('Filter Controls', () => {
    test('filter inputs are hidden when collapsed', async () => {
      // Set to collapsed BEFORE render
      localStorage.setItem('logs-filters-expanded', 'false')

      renderWithProviders(<Logs />)

      await waitFor(() => {
        expect(screen.getByText('Logs')).toBeInTheDocument()
      })

      // Filter inputs should not be visible
      expect(screen.queryByPlaceholderText('e.g. 192.168.1')).not.toBeInTheDocument()
      expect(screen.queryByPlaceholderText('e.g. 443')).not.toBeInTheDocument()
    })

  test('Query button triggers refetch', async () => {
    // Need to expand the filter panel first
    const user = userEvent.setup()
    renderWithProviders(<Logs />)

    await waitFor(() => {
      expect(screen.getByText('Logs')).toBeInTheDocument()
    })

    // Expand the filter panel
    const filtersButton = screen.getByRole('button', { name: /Filters/ })
    await user.click(filtersButton)

    // Query button should now be visible
    await waitFor(() => {
      expect(screen.getByText('Query')).toBeInTheDocument()
    })

    const queryButton = screen.getByText('Query')
    await user.click(queryButton)

    // API should have been called
    await waitFor(() => {
      expect(apiClient.api.get).toHaveBeenCalled()
    })
  })

  test('Clear button resets filters', async () => {
    // Need to expand the filter panel first
    const user = userEvent.setup()
    renderWithProviders(<Logs />)

    await waitFor(() => {
      expect(screen.getByText('Logs')).toBeInTheDocument()
    })

    // Expand the filter panel
    const filtersButton = screen.getByRole('button', { name: /Filters/ })
    await user.click(filtersButton)

    // Wait for filter inputs to be visible
    await waitFor(() => {
      expect(screen.getByPlaceholderText('e.g. 192.168.1')).toBeInTheDocument()
    })

    // Type in source IP
    const srcIpInput = screen.getByPlaceholderText('e.g. 192.168.1')
    await user.type(srcIpInput, '192.168')

    // Clear button should appear
    await waitFor(() => {
      expect(screen.getByText('Clear')).toBeInTheDocument()
    })

    await user.click(screen.getByText('Clear'))

    // Input should be cleared
    await waitFor(() => {
      expect(srcIpInput).toHaveValue('')
    })
  })
  })

  describe('Pagination', () => {
    test('shows pagination info for historical mode', async () => {
      renderWithProviders(<Logs />)

      await waitFor(() => {
        expect(screen.getByText('Logs')).toBeInTheDocument()
      })

      // Wait for logs to load
      await waitFor(() => {
        // Should show pagination with total count
        expect(screen.getByText(/Showing/)).toBeInTheDocument()
      })
    })
  })
})
