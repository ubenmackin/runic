import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import Login from './Login'
import * as apiClient from '../api/client'
import { useAuthStore } from '../store'

// Mocks
vi.mock('../hooks/useFocusTrap', () => ({ useFocusTrap: vi.fn() }))
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal()
  return { ...actual, api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() }, setAuthFailureHandler: vi.fn() }
})
const mockUseSetup = vi.fn()
vi.mock('../contexts/SetupContext', () => ({ useSetup: () => mockUseSetup() }))
vi.mock('../components/InlineError', () => ({ default: ({ message }) => message ? <div data-testid="inline-error">{message}</div> : null }))

function createWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
  return function Wrapper({ children }) { return <QueryClientProvider client={qc}><BrowserRouter>{children}</BrowserRouter></QueryClientProvider> }
}

function renderWithProviders(ui) { return render(ui, { wrapper: createWrapper() }) }

describe('Login Page', () => {
  const originalState = useAuthStore.getState()

  beforeEach(() => {
    vi.clearAllMocks()
    useAuthStore.setState({ isAuthenticated: false, username: null, role: null })
    mockUseSetup.mockReturnValue({ needsSetup: false, loading: false })
    apiClient.api.post.mockRejectedValue(new Error('Unexpected mock call'))
  })

  afterEach(() => { useAuthStore.setState(originalState) })

  test('renders sign-in form by default', () => {
    renderWithProviders(<Login />)
    expect(screen.getByText('Runic')).toBeInTheDocument()
    expect(screen.getByText('Firewall Policy Management')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeInTheDocument()
  })

  test('renders setup form when mode is setup', () => {
    mockUseSetup.mockReturnValue({ needsSetup: true, loading: false })
    renderWithProviders(<Login mode="setup" />)
    expect(screen.getByText('Welcome — Set up your admin account')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create Account' })).toBeInTheDocument()
  })

  test('shows confirm password field in setup mode', () => {
    mockUseSetup.mockReturnValue({ needsSetup: true, loading: false })
    renderWithProviders(<Login />)
    expect(screen.getByText('Confirm Password')).toBeInTheDocument()
    // Should have 2 password inputs (password + confirm)
    expect(document.querySelectorAll('input[type="password"]')).toHaveLength(2)
  })

  test('has only one password input in login mode', () => {
    renderWithProviders(<Login />)
    expect(document.querySelectorAll('input[type="password"]')).toHaveLength(1)
  })

  test('submits login form with credentials', async () => {
    const user = userEvent.setup()
    apiClient.api.post.mockResolvedValue({})
    useAuthStore.setState({ isAuthenticated: true, username: 'admin', role: 'admin' })

    renderWithProviders(<Login />)
    await user.type(document.querySelector('input[type="text"]'), 'admin')
    await user.type(document.querySelectorAll('input[type="password"]')[0], 'secret')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))

    expect(apiClient.api.post).toHaveBeenCalledWith('/auth/login', { username: 'admin', password: 'secret' })
  })

  test('button text changes during pending state', async () => {
    apiClient.api.post.mockImplementation(() => new Promise(() => {}))
    const user = userEvent.setup()

    renderWithProviders(<Login />)
    await user.type(document.querySelector('input[type="text"]'), 'admin')
    await user.type(document.querySelectorAll('input[type="password"]')[0], 'secret')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))

    expect(await screen.findByRole('button', { name: 'Please wait...' })).toBeInTheDocument()
  })

  test('displays error message on failed login', async () => {
    apiClient.api.post.mockRejectedValue(new Error('Invalid credentials'))
    const user = userEvent.setup()

    renderWithProviders(<Login />)
    await user.type(document.querySelector('input[type="text"]'), 'admin')
    await user.type(document.querySelectorAll('input[type="password"]')[0], 'wrong')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))

    expect(await screen.findByTestId('inline-error')).toHaveTextContent('Invalid credentials')
  })

  test('submits setup form with matching passwords', async () => {
    apiClient.api.post.mockResolvedValue({})
    useAuthStore.setState({ isAuthenticated: true, username: 'admin', role: 'admin' })
    const user = userEvent.setup()

    mockUseSetup.mockReturnValue({ needsSetup: true, loading: false })
    renderWithProviders(<Login />)

    await user.type(document.querySelector('input[type="text"]'), 'admin')
    const pwInputs = document.querySelectorAll('input[type="password"]')
    await user.type(pwInputs[0], 'password123')
    await user.type(pwInputs[1], 'password123')
    await user.click(screen.getByRole('button', { name: 'Create Account' }))

    expect(apiClient.api.post).toHaveBeenCalledWith('/setup', { username: 'admin', password: 'password123' })
  })

  test('shows error when passwords do not match in setup mode', async () => {
    const user = userEvent.setup()
    mockUseSetup.mockReturnValue({ needsSetup: true, loading: false })
    renderWithProviders(<Login />)

    await user.type(document.querySelector('input[type="text"]'), 'admin')
    const pwInputs = document.querySelectorAll('input[type="password"]')
    await user.type(pwInputs[0], 'password123')
    await user.type(pwInputs[1], 'different')
    await user.click(screen.getByRole('button', { name: 'Create Account' }))

    expect(await screen.findByTestId('inline-error')).toHaveTextContent('Passwords do not match')
  })

  test('shows setup-completed error and switches to login mode', async () => {
    apiClient.api.post.mockRejectedValue(new Error('Setup already completed'))
    const user = userEvent.setup()
    mockUseSetup.mockReturnValue({ needsSetup: true, loading: false })
    renderWithProviders(<Login />)

    await user.type(document.querySelector('input[type="text"]'), 'admin')
    const pwInputs = document.querySelectorAll('input[type="password"]')
    await user.type(pwInputs[0], 'password123')
    await user.type(pwInputs[1], 'password123')
    await user.click(screen.getByRole('button', { name: 'Create Account' }))

    expect(await screen.findByTestId('inline-error')).toHaveTextContent('Setup already completed')
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeInTheDocument()
  })

  test('shows error when login succeeds but session verification fails', async () => {
    apiClient.api.post.mockResolvedValue({})
    const user = userEvent.setup()
    renderWithProviders(<Login />)

    await user.type(document.querySelector('input[type="text"]'), 'admin')
    await user.type(document.querySelectorAll('input[type="password"]')[0], 'secret')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))

    expect(await screen.findByTestId('inline-error')).toHaveTextContent('Login succeeded but session verification failed')
  })
})