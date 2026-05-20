import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Services from './Services'
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
vi.mock('../hooks/ToastContext', () => ({ useToastContext: () => mockShowToast }))

// Mock API
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
    QUERY_KEYS: { services: () => ['services'] },
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
const mockServices = [
  { id: 1, name: 'SSH', protocol: 'tcp', ports: '22', description: 'Secure Shell', is_system: false },
  { id: 2, name: 'HTTP', protocol: 'tcp', ports: '80,443', description: 'Web traffic', is_system: false },
  { id: 3, name: 'DNS', protocol: 'udp', ports: '53', description: 'DNS', is_system: true },
]

describe('Services Page', () => {
  const originalState = useAuthStore.getState()

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    useAuthStore.setState({ isAuthenticated: true, username: 'testuser', role: 'admin' })
    apiClient.api.get.mockImplementation((path) => {
      if (path === '/services') return Promise.resolve(mockServices)
      return Promise.resolve([])
    })
  })

  afterEach(() => {
    useAuthStore.setState(originalState)
    localStorage.clear()
  })

  test('renders page header', async () => {
    renderWithProviders(<Services />)
    await waitFor(() => expect(screen.getByText('Services')).toBeInTheDocument())
    expect(screen.getByText(/Define port/)).toBeInTheDocument()
  })

  test('shows New Service button for admin', async () => {
    renderWithProviders(<Services />)
    await waitFor(() => { expect(screen.getByText('New Service')).toBeInTheDocument() })
  })

  test('hides New Service button for viewer', async () => {
    useAuthStore.setState({ role: 'viewer' })
    renderWithProviders(<Services />)
    await waitFor(() => { expect(screen.getByText('Services')).toBeInTheDocument() })
    expect(screen.queryByText('New Service')).not.toBeInTheDocument()
  })

  test('shows system services panel when system services exist', async () => {
    renderWithProviders(<Services />)
    await waitFor(() => { expect(screen.getByText('System Services')).toBeInTheDocument() })
  })

  test('renders service table', async () => {
    renderWithProviders(<Services />)
    await waitFor(() => {
      const table = document.querySelector('table')
      expect(table).toBeInTheDocument()
    }, { timeout: 3000 })
  })

  test('shows loading state initially', async () => {
    apiClient.api.get.mockImplementation(() => new Promise(() => {}))
    renderWithProviders(<Services />)
    expect(screen.getByLabelText(/Loading table data/)).toBeInTheDocument()
  })

  test('shows empty state when no services', async () => {
    apiClient.api.get.mockResolvedValue([])
    renderWithProviders(<Services />)
    await waitFor(() => { expect(screen.getByText('No user services yet')).toBeInTheDocument() })
  })

  test('refresh button calls API', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Services />)
    await waitFor(() => { expect(screen.getByText('Refresh')).toBeInTheDocument() })
    await user.click(screen.getByText('Refresh'))
    expect(apiClient.api.get).toHaveBeenCalled()
  })
})