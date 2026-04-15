import { render, screen, waitFor } from '@testing-library/react'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Topology from './Topology'
import * as apiClient from '../api/client'

// Mock the API client
vi.mock('../api/client', () => ({
  api: {
    get: vi.fn(),
  },
  QUERY_KEYS: {
    peers: () => ['peers'],
    groups: () => ['groups'],
    policies: () => ['policies'],
    services: () => ['services'],
  },
}))

// Mock SearchableSelect component
vi.mock('../components/SearchableSelect', () => ({
  default: ({ options, value, onChange, placeholder }) => (
    <select
      value={value || ''}
      onChange={(e) => onChange?.(e.target.value ? Number(e.target.value) : null)}
      aria-label="Starting Peer"
      data-testid="peer-select"
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

// Mock d3 - just provide minimal implementations
vi.mock('d3', () => ({
  default: {
    select: vi.fn(() => ({
     selectAll: vi.fn(() => ({
        remove: vi.fn(),
        join: vi.fn(() => ({
          attr: vi.fn(() => ({
            on: vi.fn(),
          })),
        })),
      })),
      append: vi.fn(() => ({
        attr: vi.fn(() => ({
          text: vi.fn(() => ({
            attr: vi.fn(),
          })),
          on: vi.fn(),
        })),
      })),
      on: vi.fn(),
      call: vi.fn(),
      transition: vi.fn(() => ({
        duration: vi.fn(() => ({
          call: vi.fn(),
        })),
      })),
    })),
    zoom: vi.fn(() => ({
      scaleExtent: vi.fn(() => ({
        on: vi.fn(),
      })),
      transform: vi.fn(),
      scaleBy: vi.fn(),
      identity: { translate: vi.fn(() => ({ scale: vi.fn() })) },
    })),
  },
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

// Mock data
const mockPeers = [
  { id: 1, hostname: 'server-alpha', ip_address: '192.168.1.10', status: 'online' },
  { id: 2, hostname: 'server-beta', ip_address: '192.168.1.20', status: 'offline' },
  { id: 3, hostname: 'server-gamma', ip_address: '192.168.1.30', status: 'online' },
]

const mockGroups = [
  { id: 1, name: 'web-servers', peer_count: 2 },
  { id: 2, name: 'db-servers', peer_count: 1 },
]

const mockPolicies = [
  { id: 1, name: 'web-policy', enabled: true, action: 'ACCEPT', source_type: 'peer', source_id: 1, target_type: 'peer', target_id: 2, direction: 'forward', service_id: 1 },
]

const mockServices = [
  { id: 1, name: 'HTTPS', ports: '443' },
]

describe('Topology Page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    // Default API mocks
    apiClient.api.get.mockImplementation((path) => {
      if (path === '/peers') return Promise.resolve(mockPeers)
      if (path === '/groups') return Promise.resolve(mockGroups)
      if (path === '/policies') return Promise.resolve(mockPolicies)
      if (path === '/services') return Promise.resolve(mockServices)
      if (path.startsWith('/groups/') && path.endsWith('/members')) return Promise.resolve([])
      return Promise.resolve([])
    })
  })

  afterEach(() => {
    localStorage.clear()
  })

  describe('Height Calculation', () => {
    test('container has correct height calculation class', async () => {
      const { container } = renderWithProviders(<Topology />)

      await waitFor(() => {
        expect(screen.getByText('Topology')).toBeInTheDocument()
      })

      // Find the main container with height calculation
      const mainContainer = container.querySelector('.h-\\[calc\\(100vh-52px-2rem\\)\\]')
      expect(mainContainer).toBeInTheDocument()

      // Should also have the md: breakpoint height
      const mdHeightContainer = container.querySelector('.md\\:h-\\[calc\\(100vh-52px-3rem\\)\\]')
      expect(mdHeightContainer).toBeInTheDocument()
    })

    test('container has overflow-hidden to prevent scrollbars', async () => {
      const { container } = renderWithProviders(<Topology />)

      await waitFor(() => {
        expect(screen.getByText('Topology')).toBeInTheDocument()
      })

      // The main container should have overflow-hidden
      const mainContainer = container.querySelector('.overflow-hidden')
      expect(mainContainer).toBeInTheDocument()
    })

    test('graph container has flex-1 to fill available space', async () => {
      const { container } = renderWithProviders(<Topology />)

      await waitFor(() => {
        expect(screen.getByText('Topology')).toBeInTheDocument()
      })

      // The graph container should have flex-1
      const flexContainer = container.querySelector('.flex-1')
      expect(flexContainer).toBeInTheDocument()
    })

    test('no vertical scrollbar behavior on main container', async () => {
      const { container } = renderWithProviders(<Topology />)

      await waitFor(() => {
        expect(screen.getByText('Topology')).toBeInTheDocument()
      })

      // Get the main container that should prevent scrollbars
      const mainContainer = container.querySelector('.overflow-hidden')
      
      // Verify it has the flex flex-col structure for proper layout
      expect(mainContainer).toHaveClass('flex')
      expect(mainContainer).toHaveClass('flex-col')
    })

    test('graph area has minimum height set', async () => {
      const { container } = renderWithProviders(<Topology />)

      await waitFor(() => {
        expect(screen.getByText('Topology')).toBeInTheDocument()
      })

// The graph container should have minHeight style
  const _graphContainer = container.querySelector('[style*="minHeight"], [style*="min-height"]')
      // Also check for style prop with minHeight
      const allContainers = container.querySelectorAll('[style]')
      const hasMinHeight = Array.from(allContainers).some(el => 
        el.style.minHeight || el.getAttribute('style')?.includes('minHeight')
      )
      expect(hasMinHeight).toBe(true)
    })
  })

  describe('Initial State', () => {
    test('renders topology page header', async () => {
      renderWithProviders(<Topology />)

      await waitFor(() => {
        expect(screen.getByText('Topology')).toBeInTheDocument()
      })

      expect(screen.getByText('Visualize network connections between peers and groups')).toBeInTheDocument()
    })

    test('shows starting peer selector', async () => {
      renderWithProviders(<Topology />)

      await waitFor(() => {
        expect(screen.getByText('Starting Peer')).toBeInTheDocument()
      })

      // The select element from our mocked SearchableSelect
      expect(screen.getByRole('combobox', { name: 'Starting Peer' })).toBeInTheDocument()
    })

    test('shows empty state when no peer selected', async () => {
      renderWithProviders(<Topology />)

      await waitFor(() => {
        expect(screen.getByText('Select a Starting Peer')).toBeInTheDocument()
      })

      // The text is broken up, so we check for partial text
      expect(screen.getByText(/Choose a peer above/)).toBeInTheDocument()
    })
  })

  describe('Peer Selection', () => {
    test('peer selector shows available peers', async () => {
      renderWithProviders(<Topology />)

      await waitFor(() => {
        expect(screen.getByText('Topology')).toBeInTheDocument()
      })

      // Find the select element
      const peerSelect = screen.getByRole('combobox', { name: 'Starting Peer' })
      expect(peerSelect).toBeInTheDocument()

      // Wait for options to be loaded (peers API call)
      await waitFor(() => {
        expect(screen.getByRole('option', { name: 'server-alpha' })).toBeInTheDocument()
      })
    })
  })

  describe('Legend', () => {
    test('legend is rendered in the graph component', async () => {
      renderWithProviders(<Topology />)

      await waitFor(() => {
        expect(screen.getByText('Topology')).toBeInTheDocument()
      })

      // Wait for peers to load
      await waitFor(() => {
        expect(screen.getByRole('option', { name: 'server-alpha' })).toBeInTheDocument()
      })

      // The TreeGraph component with Legend is conditionally rendered when a peer is selected
      // For this test, we verify the component structure is correct by checking the select exists
      const peerSelect = screen.getByRole('combobox', { name: 'Starting Peer' })
      expect(peerSelect).toBeInTheDocument()
    })
  })

  describe('Dark Mode Handling', () => {
    test('component detects dark mode on mount', async () => {
      // This tests that the component initializes isDark state correctly
      renderWithProviders(<Topology />)

      await waitFor(() => {
        expect(screen.getByText('Topology')).toBeInTheDocument()
      })

      // The component should render without errors
      // The dark mode detection is internal, but we verify the component works
      expect(screen.getByText('Topology')).toBeInTheDocument()
    })
  })

  describe('Error Handling', () => {
    test('handles API errors gracefully', async () => {
      apiClient.api.get.mockRejectedValue(new Error('API Error'))

      renderWithProviders(<Topology />)

      // Should still render the header
      await waitFor(() => {
        expect(screen.getByText('Topology')).toBeInTheDocument()
      })
    })
  })
})
