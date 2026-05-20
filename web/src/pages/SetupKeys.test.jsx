import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import SetupKeys from './SetupKeys'
import * as apiClient from '../api/client'
import { useAuthStore } from '../store'

// Mock dependencies
vi.mock('../hooks/useFocusTrap', () => ({ useFocusTrap: vi.fn() }))
vi.mock('../hooks/useTableSort', () => ({
  useTableSort: vi.fn(() => ({
    sortConfig: { key: 'hostname', direction: 'asc' },
    handleSort: vi.fn(),
  })),
}))
vi.mock('../hooks/usePagination', () => ({
  usePagination: vi.fn((data, _key) => ({
    paginatedData: data,
    totalPages: Math.ceil(data.length / 25),
    showingRange: `Showing 1 - ${Math.min(data.length, 25)} of ${data.length}`,
    page: 1,
    rowsPerPage: 25,
    onPageChange: vi.fn(),
    onRowsPerPageChange: vi.fn(),
    totalItems: data.length,
  })),
}))
vi.mock('../hooks/useTableFilter', () => ({
  useTableFilter: vi.fn((data) => data),
}))
vi.mock('../utils/formatTime', () => ({
  formatRelativeTime: (date) => date ? '2 hours ago' : 'never',
}))

// Mock toast
const mockShowToast = vi.fn()
vi.mock('../hooks/ToastContext', () => ({ useToastContext: () => ({ showToast: mockShowToast }) }))

// Mock API client
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() },
    QUERY_KEYS: actual.QUERY_KEYS,
    setAuthFailureHandler: vi.fn(),
  }
})

const mockPeers = [
  {
    id: 'p1',
    hostname: 'server-alpha',
    ip_address: '192.168.1.10',
    is_manual: false,
    hmac_key_last_rotated_at: '2025-01-14T10:00:00Z',
  },
  {
    id: 'p2',
    hostname: 'server-beta',
    ip_address: '192.168.1.20',
    is_manual: false,
    hmac_key_last_rotated_at: null,
  },
  {
    id: 'p3',
    hostname: 'manual-peer',
    ip_address: '192.168.1.30',
    is_manual: true,
    hmac_key_last_rotated_at: '2025-01-10T10:00:00Z',
  },
]

const mockTokens = [
  {
    id: 't1',
    token: 'tok12345678',
    description: 'Production server #3',
    is_revoked: false,
    used_at: null,
    used_by_hostname: null,
    created_at: '2025-01-15T08:00:00Z',
  },
  {
    id: 't2',
    token: 'tok87654321',
    description: 'Test server',
    is_revoked: false,
    used_at: '2025-01-14T12:00:00Z',
    used_by_hostname: 'test-host',
    created_at: '2025-01-10T08:00:00Z',
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

// Helper to find tab buttons by their partial text content
function getSetupKeysTab() {
  return screen.getAllByRole('button').find(b => b.textContent.includes('Setup Keys'))
}
function getRegistrationTokensTab() {
  return screen.getAllByRole('button').find(b => b.textContent.includes('Registration Tokens'))
}

describe('SetupKeys Page', () => {
  const originalState = useAuthStore.getState()

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    useAuthStore.setState({ isAuthenticated: true, username: 'admin', role: 'admin' })
    apiClient.api.get.mockImplementation((path) => {
      if (path === '/peers') return Promise.resolve(mockPeers)
      if (path === '/registration-tokens') return Promise.resolve(mockTokens)
      return Promise.resolve([])
    })
    apiClient.api.post.mockResolvedValue({ rotation_token: 'rot-123' })
    apiClient.api.delete.mockResolvedValue({})
  })

  afterEach(() => {
    useAuthStore.setState(originalState)
    localStorage.clear()
  })

  test('renders page header', async () => {
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      // PageHeader title and tab button both have "Setup Keys"
      expect(screen.getAllByText(/Setup Keys/).length).toBeGreaterThan(0)
    })
    expect(screen.getByText('Manage per-peer HMAC key rotation and agent registration tokens')).toBeInTheDocument()
  })

  test('shows Setup Keys tab by default', async () => {
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(getSetupKeysTab()).toBeTruthy()
    })
  })

  test('shows Registration Tokens tab button', async () => {
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(getRegistrationTokensTab()).toBeTruthy()
    })
  })

  test('switches to Registration Tokens tab', async () => {
    const user = userEvent.setup()
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(getRegistrationTokensTab()).toBeTruthy()
    })
    await user.click(getRegistrationTokensTab())
    await waitFor(() => {
      expect(screen.getByText('Generate Token')).toBeInTheDocument()
    })
  })

  test('shows peer list in Setup Keys tab', async () => {
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(screen.getByText('server-alpha')).toBeInTheDocument()
      expect(screen.getByText('server-beta')).toBeInTheDocument()
    })
  })

  test('hides Rotate All Keys button for non-admin', async () => {
    useAuthStore.setState({ role: 'viewer' })
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(screen.getAllByText(/Setup Keys/).length).toBeGreaterThan(0)
    })
    const rotateAllBtn = screen.queryByRole('button', { name: /Rotate All Keys/ })
    expect(rotateAllBtn).not.toBeInTheDocument()
  })

  test('shows Rotate All Keys button for admin', async () => {
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(screen.getByText('Rotate All Keys')).toBeInTheDocument()
    })
  })

  test('shows rotation status for peers', async () => {
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      // server-alpha was recently rotated
      expect(screen.getByText('server-alpha')).toBeInTheDocument()
      // server-beta was never rotated
      expect(screen.getByText('server-beta')).toBeInTheDocument()
    })
  })

  test('excludes manual peers from key list', async () => {
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(screen.getByText('server-alpha')).toBeInTheDocument()
    })
    // manual-peer is_manual=true, should not appear in the agent peers table
    expect(screen.queryByText('manual-peer')).not.toBeInTheDocument()
  })

  test('shows generate token button for admin in tokens tab', async () => {
    const user = userEvent.setup()
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(getRegistrationTokensTab()).toBeTruthy()
    })
    await user.click(getRegistrationTokensTab())
    await waitFor(() => {
      expect(screen.getByText('Generate Token')).toBeInTheDocument()
    })
  })

  test('opens generate token modal', async () => {
    const user = userEvent.setup()
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(getRegistrationTokensTab()).toBeTruthy()
    })
    await user.click(getRegistrationTokensTab())
    await waitFor(() => {
      expect(screen.getByText('Generate Token')).toBeInTheDocument()
    })
    await user.click(screen.getByText('Generate Token'))
    await waitFor(() => {
      expect(screen.getByText('Generate Registration Token')).toBeInTheDocument()
    })
  })

  test('generates token with description', async () => {
    const user = userEvent.setup()
    apiClient.api.post.mockResolvedValueOnce({ full_token: 'new-token-123', description: 'Test token' })

    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(getRegistrationTokensTab()).toBeTruthy()
    })
    await user.click(getRegistrationTokensTab())
    await waitFor(() => {
      expect(screen.getByText('Generate Token')).toBeInTheDocument()
    })
    await user.click(screen.getByText('Generate Token'))
    await waitFor(() => {
      expect(screen.getByText('Generate Registration Token')).toBeInTheDocument()
    })

    const descInput = screen.getByPlaceholderText('e.g., Production server #3')
    await user.type(descInput, 'Test token')
    // Click the Generate button in the modal (not the header one)
    const generateButtons = screen.getAllByRole('button').filter(b => b.textContent.trim() === 'Generate')
    await user.click(generateButtons[generateButtons.length - 1])

    await waitFor(() => {
      expect(apiClient.api.post).toHaveBeenCalledWith('/registration-tokens', { description: 'Test token' })
    })
  })

  test('shows generated token in result modal', async () => {
    const user = userEvent.setup()
    apiClient.api.post.mockResolvedValueOnce({ full_token: 'new-token-123', description: 'Test token' })

    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(getRegistrationTokensTab()).toBeTruthy()
    })
    await user.click(getRegistrationTokensTab())
    await waitFor(() => {
      expect(screen.getByText('Generate Token')).toBeInTheDocument()
    })
    await user.click(screen.getByText('Generate Token'))
    await waitFor(() => {
      expect(screen.getByText('Generate Registration Token')).toBeInTheDocument()
    })

    const descInput = screen.getByPlaceholderText('e.g., Production server #3')
    await user.type(descInput, 'Test token')
    const generateButtons = screen.getAllByRole('button').filter(b => b.textContent.trim() === 'Generate')
    await user.click(generateButtons[generateButtons.length - 1])

    await waitFor(() => {
      expect(screen.getByText('Registration Token Generated')).toBeInTheDocument()
      expect(screen.getByText('new-token-123')).toBeInTheDocument()
    })
  })

  test('shows token list in tokens tab', async () => {
    const user = userEvent.setup()
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(getRegistrationTokensTab()).toBeTruthy()
    })
    await user.click(getRegistrationTokensTab())
    await waitFor(() => {
      // Token descriptions should be visible
      expect(screen.getByText('Production server #3')).toBeInTheDocument()
      expect(screen.getByText('Test server')).toBeInTheDocument()
    })
  })

  test('shows token status badges', async () => {
    const user = userEvent.setup()
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(getRegistrationTokensTab()).toBeTruthy()
    })
    await user.click(getRegistrationTokensTab())
    await waitFor(() => {
      expect(screen.getByText('Active')).toBeInTheDocument()
      expect(screen.getByText('Used')).toBeInTheDocument()
    })
  })

  test('opens revoke confirmation modal', async () => {
    const user = userEvent.setup()
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(getRegistrationTokensTab()).toBeTruthy()
    })
    await user.click(getRegistrationTokensTab())
    await waitFor(() => {
      expect(screen.getByText('Active')).toBeInTheDocument()
    })

    const revokeButtons = screen.getAllByTitle('Revoke')
    await user.click(revokeButtons[0])

    await waitFor(() => {
      expect(screen.getByText('Revoke Registration Token?')).toBeInTheDocument()
    })
  })

  test('confirms token revocation', async () => {
    const user = userEvent.setup()
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(getRegistrationTokensTab()).toBeTruthy()
    })
    await user.click(getRegistrationTokensTab())
    await waitFor(() => {
      expect(screen.getByText('Active')).toBeInTheDocument()
    })

    const revokeButtons = screen.getAllByTitle('Revoke')
    await user.click(revokeButtons[0])

    await waitFor(() => {
      expect(screen.getByText('Revoke Registration Token?')).toBeInTheDocument()
    })
    await user.click(screen.getByText('Revoke'))

    await waitFor(() => {
      expect(apiClient.api.delete).toHaveBeenCalledWith('/registration-tokens/t1')
    })
  })

  test('shows empty state when no peers', async () => {
    apiClient.api.get.mockImplementation((path) => {
      if (path === '/peers') return Promise.resolve([])
      if (path === '/registration-tokens') return Promise.resolve(mockTokens)
      return Promise.resolve([])
    })
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(screen.getByText('No peers found. Add peers to manage their keys.')).toBeInTheDocument()
    })
  })

  test('shows empty state when no tokens', async () => {
    apiClient.api.get.mockImplementation((path) => {
      if (path === '/peers') return Promise.resolve(mockPeers)
      if (path === '/registration-tokens') return Promise.resolve([])
      return Promise.resolve([])
    })
    const user = userEvent.setup()
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(getRegistrationTokensTab()).toBeTruthy()
    })
    await user.click(getRegistrationTokensTab())
    await waitFor(() => {
      expect(screen.getByText('No registration tokens yet. Generate one to allow agents to register.')).toBeInTheDocument()
    })
  })

  test('shows rotate confirmation for single peer', async () => {
    const user = userEvent.setup()
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(screen.getByText('server-alpha')).toBeInTheDocument()
    })

    const rotateButtons = screen.getAllByTitle('Rotate Key')
    await user.click(rotateButtons[0])

    await waitFor(() => {
      expect(screen.getByText(/Rotate Key for/)).toBeInTheDocument()
    })
  })

  test('shows rotate all confirmation modal', async () => {
    const user = userEvent.setup()
    renderWithProviders(<SetupKeys />)
    await waitFor(() => {
      expect(screen.getByText('Rotate All Keys')).toBeInTheDocument()
    })

    await user.click(screen.getByText('Rotate All Keys'))
    await waitFor(() => {
      expect(screen.getByText('Rotate All Peer Keys?')).toBeInTheDocument()
    })
  })
})