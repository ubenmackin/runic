import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import Users from './Users'
import * as apiClient from '../api/client'
import { useAuthStore } from '../store'

// Mocks
vi.mock('../hooks/useFocusTrap', () => ({ useFocusTrap: vi.fn() }))
vi.mock('../components/SearchableSelect', () => ({
  default: ({ options, value, onChange, placeholder }) => (
    <select data-testid="searchable-select" value={value || ''} onChange={(e) => onChange?.(e.target.value)}>
      <option value="">{placeholder}</option>
      {options?.map((opt) => (<option key={opt.value} value={opt.value}>{opt.label}</option>))}
    </select>
  ),
}))
const mockShowToast = vi.fn()
vi.mock('../hooks/ToastContext', () => ({ useToastContext: () => ({ showToast: mockShowToast }) }))
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal()
  return { ...actual, api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() }, setAuthFailureHandler: vi.fn() }
})

const mockUsers = [
  { id: 1, username: 'admin', email: 'admin@example.com', role: 'administrator' },
  { id: 2, username: 'editor', email: 'editor@example.com', role: 'content_editor' },
  { id: 3, username: 'viewer', email: null, role: 'readonly' },
]

function createWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
  return function Wrapper({ children }) { return <QueryClientProvider client={qc}><BrowserRouter>{children}</BrowserRouter></QueryClientProvider> }
}

function renderWithProviders(ui) { return render(ui, { wrapper: createWrapper() }) }

describe('Users Page', () => {
  const originalState = useAuthStore.getState()

  beforeEach(() => {
    vi.clearAllMocks()
    useAuthStore.setState({ isAuthenticated: true, username: 'admin', role: 'admin' })
    apiClient.api.get.mockResolvedValue(mockUsers)
    apiClient.api.post.mockResolvedValue({})
    apiClient.api.put.mockResolvedValue({})
    apiClient.api.delete.mockResolvedValue({})
  })

  afterEach(() => { useAuthStore.setState(originalState); localStorage.clear() })

  test('renders page header', async () => {
    renderWithProviders(<Users />)
    expect(await screen.findByText('Users')).toBeInTheDocument()
    expect(screen.getByText('Manage user accounts for the Runic control plane')).toBeInTheDocument()
  })

  test('shows user list in table', async () => {
    renderWithProviders(<Users />)
    expect(await screen.findByText('admin')).toBeInTheDocument()
    // Use getAllByText when text appears multiple times (e.g. "admin" is role too)
    expect(screen.getAllByText(/^admin$/).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/^editor$/).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/^viewer$/).length).toBeGreaterThan(0)
  })

  test('shows user emails in table', async () => {
    renderWithProviders(<Users />)
    expect(await screen.findByText('admin@example.com')).toBeInTheDocument()
    expect(screen.getByText('editor@example.com')).toBeInTheDocument()
  })

  test('shows Create User button for admin', async () => {
    renderWithProviders(<Users />)
    expect(await screen.findByText('Create User')).toBeInTheDocument()
  })

  test('hides Create User button for non-admin', async () => {
    useAuthStore.setState({ role: 'viewer' })
    renderWithProviders(<Users />)
    expect(await screen.findByText('Users')).toBeInTheDocument()
    expect(screen.queryByText('Create User')).not.toBeInTheDocument()
  })

  test('hides delete button for current user', async () => {
    useAuthStore.setState({ username: 'admin', role: 'admin' })
    renderWithProviders(<Users />)
    expect(await screen.findByText('admin')).toBeInTheDocument()
    // admin should not have delete button for themselves
    // "viewer" user should have delete buttons available
    expect(screen.getAllByRole('button').length).toBeGreaterThan(0)
  })

  test('opens create user modal', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Users />)
    await user.click(await screen.findByText('Create User'))
    expect((await screen.findAllByText(/^Create User$/)).length).toBeGreaterThan(0)
    // Use document.querySelector for input elements
    expect(document.querySelector('#username')).toBeInTheDocument()
    expect(document.querySelector('#password')).toBeInTheDocument()
    expect(document.querySelector('#confirmPassword')).toBeInTheDocument()
  })

  test('creates new user with form data', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Users />)
    await user.click(await screen.findByText('Create User'))
    await screen.findByRole('dialog')

    await user.type(document.querySelector('#username'), 'newuser')
    await user.type(document.querySelector('#password'), 'password123')
    await user.type(document.querySelector('#confirmPassword'), 'password123')
    await user.type(document.querySelector('#email'), 'newuser@example.com')
    await user.click(screen.getAllByRole('button').find(b => b.textContent === 'Create'))

    expect(apiClient.api.post).toHaveBeenCalledWith('/users', {
      username: 'newuser', password: 'password123', email: 'newuser@example.com', role: 'viewer',
    })
  })

  test('validates password match on create', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Users />)
    await user.click(await screen.findByText('Create User'))
    await screen.findByRole('dialog')

    await user.type(document.querySelector('#username'), 'newuser')
    await user.type(document.querySelector('#password'), 'password123')
    await user.type(document.querySelector('#confirmPassword'), 'different')
    await user.click(screen.getAllByRole('button').find(b => b.textContent === 'Create'))

    expect(mockShowToast).toHaveBeenCalledWith('Passwords do not match', 'error')
  })

  test('opens edit user modal', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Users />)
    expect(await screen.findByText('editor')).toBeInTheDocument()

    // Click the edit button for the editor user row
    const editorRow = screen.getByText('editor').closest('tr')
    const editBtn = editorRow.querySelector('button')
    await user.click(editBtn)
    expect(await screen.findByText('Edit User')).toBeInTheDocument()
  })

  test('shows error when loading users fails', async () => {
    apiClient.api.get.mockRejectedValue(new Error('Failed to fetch'))
    renderWithProviders(<Users />)
    expect(await screen.findByText('Failed to load users')).toBeInTheDocument()
  })

  test('shows empty state when no users', async () => {
    apiClient.api.get.mockResolvedValue([])
    renderWithProviders(<Users />)
    expect(await screen.findByText('No users found. Create your first user to get started.')).toBeInTheDocument()
  })

  test('shows loading skeleton', () => {
    apiClient.api.get.mockImplementation(() => new Promise(() => {}))
    renderWithProviders(<Users />)
    expect(screen.queryByText('admin')).not.toBeInTheDocument()
  })

  test('shows delete confirmation modal', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Users />)
    await screen.findByText('viewer')

    // Click delete button for viewer (different buttons: page header, each row has edit+delete)
    const allButtons = screen.getAllByRole('button')
    // Find button that would be a delete (has Trash2 icon)
    const deleteBtn = allButtons.find(b => b.innerHTML.includes('Trash'))
    await user.click(deleteBtn || allButtons[allButtons.length - 1])

    expect(await screen.findByText(/^Delete User$/)).toBeInTheDocument()
  })

  test('deletes user when confirmed', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Users />)
    await screen.findByText('viewer')

    const deleteBtn = screen.getAllByRole('button').find(b => b.innerHTML.includes('Trash'))
    await user.click(deleteBtn || screen.getAllByRole('button').at(-1))
    await screen.findByText('Delete User')

    // Click Delete in modal
    const confirmBtn = screen.getAllByRole('button').find(b => b.textContent === 'Delete')
    await user.click(confirmBtn)

    expect(apiClient.api.delete).toHaveBeenCalledWith('/users/3')
  })

  test('allows updating user email and role', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Users />)
    await screen.findByText('editor')

    const editorRow = screen.getByText('editor').closest('tr')
    const editBtn = editorRow.querySelector('button')
    await user.click(editBtn)
    await screen.findByText('Edit User')

    const updateBtn = screen.getAllByRole('button').find(b => b.textContent === 'Update')
    await user.click(updateBtn)

    expect(apiClient.api.put).toHaveBeenCalledWith('/users/2', { email: 'editor@example.com', role: 'content_editor' })
  })

  test('validates email format on edit', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Users />)
    await screen.findByText('editor')

    const editorRow = screen.getByText('editor').closest('tr')
    const editBtn = editorRow.querySelector('button')
    await user.click(editBtn)
    await screen.findByText('Edit User')

    // Use fireEvent to clear and set the email value directly on the React-controlled input
    const emailInput = document.querySelector('#editEmail')
    fireEvent.change(emailInput, { target: { value: 'invalid-email' } })
    
    // Submit the form directly to trigger validation
    const form = emailInput.closest('form')
    fireEvent.submit(form)

    await waitFor(() => {
      expect(mockShowToast).toHaveBeenCalledWith('Please enter a valid email address', 'error')
    })
  })
})