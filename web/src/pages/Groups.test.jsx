import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Groups from './Groups'
import * as apiClient from '../api/client'
import { useAuthStore } from '../store'

// Mock dependencies
vi.mock('../hooks/useIsMobile', () => ({ useIsMobile: () => false }))
vi.mock('../hooks/useFocusTrap', () => ({ useFocusTrap: vi.fn() }))
vi.mock('react-router-dom', () => ({ useLocation: () => ({ state: null }) }))
vi.mock('../components/SearchableSelect', () => ({
  default: ({ options, value, onChange, placeholder }) => (
    <select data-testid="searchable-select" value={value || ''} onChange={(e) => onChange?.(e.target.value)}>
      <option value="">{placeholder}</option>
      {options?.map((opt) => (<option key={opt.value} value={opt.value}>{opt.label}</option>))}
    </select>
  ),
}))

// Mock toast
const mockShowToast = vi.fn()
vi.mock('../hooks/ToastContext', () => ({ useToastContext: () => ({ showToast: mockShowToast }) }))

// Mock API
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
    QUERY_KEYS: { groups: () => ['groups'], peers: () => ['peers'], members: (id) => ['groups', id, 'members'] },
    setAuthFailureHandler: vi.fn(),
  }
})

// Helpers
function createWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
  return function Wrapper({ children }) { return <QueryClientProvider client={qc}>{children}</QueryClientProvider> }
}

function renderWithProviders(ui) { return render(ui, { wrapper: createWrapper() }) }

// Data
const mockGroups = [
  { id: 1, name: 'web-servers', description: 'Web servers', peer_count: 2, policy_count: 3, is_system: false },
  { id: 2, name: 'db-servers', description: 'DB servers', peer_count: 1, policy_count: 1, is_system: false },
  { id: 3, name: 'system-group', description: 'System group', peer_count: 5, policy_count: 2, is_system: true },
]

describe('Groups Page', () => {
  const originalState = useAuthStore.getState()

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    useAuthStore.setState({ isAuthenticated: true, username: 'testuser', role: 'admin' })
    apiClient.api.get.mockImplementation((path) => {
      if (path === '/groups') return Promise.resolve(mockGroups)
      if (path === '/peers') return Promise.resolve([{ id: 1, hostname: 'server-alpha', ip_address: '192.168.1.10' }])
      if (path.startsWith('/groups/') && path.endsWith('/members')) return Promise.resolve([])
      return Promise.resolve([])
    })
  })

  afterEach(() => {
    useAuthStore.setState(originalState)
    localStorage.clear()
  })

  test('renders page header', async () => {
    renderWithProviders(<Groups />)
    await waitFor(() => expect(screen.getByText('Groups')).toBeInTheDocument())
    expect(screen.getByText(/Organize peers/)).toBeInTheDocument()
  })

  test('shows New Group button for admin', async () => {
    renderWithProviders(<Groups />)
    await waitFor(() => { expect(screen.getByText('New Group')).toBeInTheDocument() })
  })

  test('hides New Group button for viewer', async () => {
    useAuthStore.setState({ role: 'viewer' })
    renderWithProviders(<Groups />)
    await waitFor(() => { expect(screen.getByText('Groups')).toBeInTheDocument() })
    expect(screen.queryByText('New Group')).not.toBeInTheDocument()
  })

  test('shows system groups panel when system groups exist', async () => {
    renderWithProviders(<Groups />)
    await waitFor(() => { expect(screen.getByText('System Groups')).toBeInTheDocument() })
  })

  test('renders group table', async () => {
    renderWithProviders(<Groups />)
    await waitFor(() => {
      const table = document.querySelector('table')
      expect(table).toBeInTheDocument()
    }, { timeout: 3000 })
  })

  test('shows loading state initially', async () => {
    apiClient.api.get.mockImplementation(() => new Promise(() => {}))
    renderWithProviders(<Groups />)
    expect(screen.getByLabelText(/Loading table data/)).toBeInTheDocument()
  })

  test('shows empty state when no groups', async () => {
    apiClient.api.get.mockImplementation((path) => {
      if (path === '/groups') return Promise.resolve([])
      return Promise.resolve([])
    })
    renderWithProviders(<Groups />)
    await waitFor(() => { expect(screen.getByText('No user groups yet')).toBeInTheDocument() })
  })

  test('refresh button calls API', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Groups />)
    await waitFor(() => { expect(screen.getByText('Refresh')).toBeInTheDocument() })
    await user.click(screen.getByText('Refresh'))
    expect(apiClient.api.get).toHaveBeenCalled()
  })
})