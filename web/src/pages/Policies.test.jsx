import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Policies from './Policies'
import * as apiClient from '../api/client'
import { useAuthStore } from '../store'

// Mock dependencies
vi.mock('../hooks/useIsMobile', () => ({ useIsMobile: () => false }))
vi.mock('../hooks/useFocusTrap', () => ({ useFocusTrap: vi.fn() }))
vi.mock('../hooks/useSSE', () => ({ useSSE: vi.fn() }))
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
vi.mock('../hooks/ToastContext', () => ({ useToastContext: () => mockShowToast }))

// Mock API client
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() },
    QUERY_KEYS: { policies: () => ['policies'], peers: () => ['peers'], groups: () => ['groups'], services: () => ['services'] },
    parseCompositePeerValue: actual.parseCompositePeerValue,
    setAuthFailureHandler: vi.fn(),
  }
})

// Helpers
function createWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
  return function Wrapper({ children }) { return <QueryClientProvider client={qc}>{children}</QueryClientProvider> }
}

function renderWithProviders(ui) {
  return render(ui, { wrapper: createWrapper() })
}

// Data
const mockPolicies = [
  { id: 1, name: 'allow-ssh', description: 'SSH access', source_type: 'group', source_id: 1, service_id: 1, target_type: 'peer', target_id: 2, action: 'ACCEPT', priority: 100, enabled: true },
  { id: 2, name: 'block-web', description: 'Block web', source_type: 'peer', source_id: 2, service_id: 2, target_type: 'group', target_id: 1, action: 'DENY', priority: 200, enabled: false },
]

describe('Policies Page', () => {
  const originalState = useAuthStore.getState()

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    useAuthStore.setState({ isAuthenticated: true, username: 'testuser', role: 'admin' })
    apiClient.api.get.mockImplementation((path) => {
      if (path === '/policies') return Promise.resolve(mockPolicies)
      if (path === '/peers') return Promise.resolve([{ id: 1, hostname: 'server-alpha', ips: [{ id: 1, ip_address: '192.168.1.10' }] }])
      if (path === '/groups') return Promise.resolve([{ id: 1, name: 'web-servers' }])
      if (path === '/services') return Promise.resolve([{ id: 1, name: 'SSH', ports: '22' }])
      if (path === '/policies/special-targets') return Promise.resolve([{ id: 6, name: '__any_ip__', display_name: 'Any IP' }])
      return Promise.resolve([])
    })
  })

  afterEach(() => {
    useAuthStore.setState(originalState)
    localStorage.clear()
  })

  test('renders page header', async () => {
    renderWithProviders(<Policies />)
    await waitFor(() => expect(screen.getByText('Policies')).toBeInTheDocument())
    expect(screen.getByText(/Create firewall rules/)).toBeInTheDocument()
  })

  test('shows New Policy button for admin', async () => {
    renderWithProviders(<Policies />)
    await waitFor(() => { expect(screen.getByText('New Policy')).toBeInTheDocument() })
  })

  test('hides New Policy button for viewer', async () => {
    useAuthStore.setState({ role: 'viewer' })
    renderWithProviders(<Policies />)
    await waitFor(() => { expect(screen.getByText('Policies')).toBeInTheDocument() })
    expect(screen.queryByText('New Policy')).not.toBeInTheDocument()
  })

  test('shows system rules panel collapsed', async () => {
    renderWithProviders(<Policies />)
    await waitFor(() => { expect(screen.getByText('System Rules')).toBeInTheDocument() })
    expect(screen.queryByText('Local loopback')).not.toBeInTheDocument()
  })

  test('can expand system rules', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Policies />)
    await waitFor(() => { expect(screen.getByText('System Rules')).toBeInTheDocument() })
    await user.click(screen.getByText('System Rules'))
    await waitFor(() => { expect(screen.getByText(/Loopback/)).toBeInTheDocument() })
  })

  test('renders policy table', async () => {
    renderWithProviders(<Policies />)
    await waitFor(() => {
      const table = document.querySelector('table')
      expect(table).toBeInTheDocument()
    }, { timeout: 3000 })
  })

  test('shows loading state initially', async () => {
    apiClient.api.get.mockImplementation(() => new Promise(() => {}))
    renderWithProviders(<Policies />)
    expect(screen.getByLabelText(/Loading table data/)).toBeInTheDocument()
  })

  test('shows empty state when no policies', async () => {
    apiClient.api.get.mockResolvedValue([])
    renderWithProviders(<Policies />)
    await waitFor(() => { expect(screen.getByText('Policies')).toBeInTheDocument() })
  })

  test('refresh button calls API', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Policies />)
    await waitFor(() => { expect(screen.getByText('Refresh')).toBeInTheDocument() })
    await user.click(screen.getByText('Refresh'))
    expect(apiClient.api.get).toHaveBeenCalled()
  })
})