import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import _userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import TopNav from './TopNav'
import { useAuthStore } from '../store'

// Mock useAuth hook
vi.mock('../hooks/useAuth', () => ({
  useAuth: () => ({
    isAdmin: useAuthStore.getState().role === 'admin',
  }),
}))

// Mock the API client - needed for version query
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    getVersion: () => Promise.resolve({ version: '1.0.0-test' }),
  }
})

// Mock useIsMobile hook - default to false (desktop)
const mockIsMobile = vi.fn(() => false)
vi.mock('../hooks/useIsMobile', () => ({
  useIsMobile: () => mockIsMobile(),
}))

// Mock usePendingChanges hook
vi.mock('../contexts/PendingChangesContext', () => ({
  usePendingChanges: () => ({
    totalPendingCount: 0,
    pendingChanges: null,
    isLoading: false,
    error: null,
  }),
}))

// Helper to render with router
function renderWithRouter(ui, { route = '/' } = {}) {
  window.history.pushState({}, 'Test page', route)
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

  const wrapper = ({ children }) => (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        {children}
      </BrowserRouter>
    </QueryClientProvider>
  )

  return render(ui, { wrapper })
}

describe('TopNav', () => {
  const originalState = useAuthStore.getState()

  beforeEach(() => {
    vi.clearAllMocks()
    useAuthStore.setState({
      isAuthenticated: true,
      username: 'testuser',
      role: 'admin',
    })
    // Clear localStorage
    localStorage.clear()
  })

  afterEach(() => {
    useAuthStore.setState(originalState)
  })

  describe('rendering', () => {
    test('renders brand logo', () => {
      renderWithRouter(<TopNav />)

      expect(screen.getByText('RUNIC')).toBeInTheDocument()
    })

    test('renders username', () => {
      useAuthStore.setState({ username: 'john_doe' })

      renderWithRouter(<TopNav />)

      expect(screen.getByText('john_doe')).toBeInTheDocument()
    })

    test('renders desktop navigation items', () => {
      renderWithRouter(<TopNav />)

      expect(screen.getByText('Dashboard')).toBeInTheDocument()
      expect(screen.getByText('Topology')).toBeInTheDocument()
    })

    test('renders Access Control dropdown trigger', () => {
      renderWithRouter(<TopNav />)

      expect(screen.getByText('Access Control')).toBeInTheDocument()
    })

    test('renders Logs dropdown trigger', () => {
      renderWithRouter(<TopNav />)

      expect(screen.getByText('Logs')).toBeInTheDocument()
    })

    test('renders Settings dropdown trigger', () => {
      renderWithRouter(<TopNav />)

      expect(screen.getByText('Settings')).toBeInTheDocument()
    })
  })

  describe('active states', () => {
    test('highlights active nav item with aria-current', () => {
      renderWithRouter(<TopNav />, { route: '/topology' })

      // The Topology nav item should have aria-current="page"
      const topologyLink = screen.getByText('Topology').closest('a')
      expect(topologyLink).toHaveAttribute('aria-current', 'page')
    })

    test('highlights Dashboard as active on root route', () => {
      renderWithRouter(<TopNav />, { route: '/' })

      const dashboardLink = screen.getByText('Dashboard').closest('a')
      expect(dashboardLink).toHaveAttribute('aria-current', 'page')
    })

    test('inactive nav items do not have aria-current', () => {
      renderWithRouter(<TopNav />, { route: '/topology' })

      // Dashboard should be inactive
      const dashboardLink = screen.getByText('Dashboard').closest('a')
      expect(dashboardLink).not.toHaveAttribute('aria-current')
    })
  })

  describe('parent menu highlighting', () => {
    test('highlights Access Control parent when child route is active', () => {
      renderWithRouter(<TopNav />, { route: '/peers' })

      // Access Control button should show active state via data-active attribute
      const accessControlButton = screen.getByText('Access Control').closest('button')
      expect(accessControlButton).toHaveAttribute('data-active', 'true')
    })

    test('highlights Access Control parent for /groups route', () => {
      renderWithRouter(<TopNav />, { route: '/groups' })

      const accessControlButton = screen.getByText('Access Control').closest('button')
      expect(accessControlButton).toHaveAttribute('data-active', 'true')
    })

    test('highlights Access Control parent for /services route', () => {
      renderWithRouter(<TopNav />, { route: '/services' })

      const accessControlButton = screen.getByText('Access Control').closest('button')
      expect(accessControlButton).toHaveAttribute('data-active', 'true')
    })

    test('highlights Access Control parent for /policies route', () => {
      renderWithRouter(<TopNav />, { route: '/policies' })

      const accessControlButton = screen.getByText('Access Control').closest('button')
      expect(accessControlButton).toHaveAttribute('data-active', 'true')
    })

    test('highlights Logs parent when /logs route is active', () => {
      renderWithRouter(<TopNav />, { route: '/logs' })

      const logsButton = screen.getByText('Logs').closest('button')
      expect(logsButton).toHaveAttribute('data-active', 'true')
    })

    test('highlights Logs parent when /alerts route is active', () => {
      renderWithRouter(<TopNav />, { route: '/alerts' })

      const logsButton = screen.getByText('Logs').closest('button')
      expect(logsButton).toHaveAttribute('data-active', 'true')
    })

    test('highlights Settings parent when /setup-keys route is active', () => {
      renderWithRouter(<TopNav />, { route: '/setup-keys' })

      const settingsButton = screen.getByText('Settings').closest('button')
      expect(settingsButton).toHaveAttribute('data-active', 'true')
    })

    test('highlights Settings parent when /users route is active', () => {
      renderWithRouter(<TopNav />, { route: '/users' })

      const settingsButton = screen.getByText('Settings').closest('button')
      expect(settingsButton).toHaveAttribute('data-active', 'true')
    })

    test('highlights Settings parent when /settings route is active', () => {
      renderWithRouter(<TopNav />, { route: '/settings' })

      const settingsButton = screen.getByText('Settings').closest('button')
      expect(settingsButton).toHaveAttribute('data-active', 'true')
    })

  test('dropdown item shows active styling when route matches', async () => {
    renderWithRouter(<TopNav />, { route: '/peers' })

    // Open the dropdown first by hovering
    const accessControlButton = screen.getByText('Access Control').closest('button')
    const dropdownContainer = accessControlButton.parentElement
    fireEvent.mouseEnter(dropdownContainer)

    // Wait for dropdown to open
    await waitFor(() => {
      expect(screen.getByText('Peers')).toBeInTheDocument()
    })

    // Find all anchor elements in the nav - the dropdown item should have active styling
    const allLinks = document.querySelectorAll('nav a')
    // Find the Peers link (should be the one in the dropdown menu)
    const peersLink = Array.from(allLinks).find(link => link.textContent.includes('Peers'))
    expect(peersLink).toBeTruthy()
    expect(peersLink).toHaveAttribute('aria-current', 'page')
  })
  })

  describe('submenu hover behavior', () => {
    test('dropdown opens on mouse enter', async () => {
      renderWithRouter(<TopNav />)

      const accessControlButton = screen.getByText('Access Control').closest('button')
      const dropdownContainer = accessControlButton.parentElement

      // Simulate mouse enter
      fireEvent.mouseEnter(dropdownContainer)

      // Dropdown should open and show menu items
      await waitFor(() => {
        expect(screen.getByText('Peers')).toBeInTheDocument()
        expect(screen.getByText('Groups')).toBeInTheDocument()
        expect(screen.getByText('Services')).toBeInTheDocument()
        expect(screen.getByText('Policies')).toBeInTheDocument()
      })
    })

  test('dropdown has delay before closing on mouse leave', async () => {
    renderWithRouter(<TopNav />)

    const accessControlButton = screen.getByText('Access Control').closest('button')
    const dropdownContainer = accessControlButton.parentElement

    // Open dropdown
    fireEvent.mouseEnter(dropdownContainer)
    await waitFor(() => {
      expect(screen.getByText('Peers')).toBeInTheDocument()
    })

    // Simulate mouse leave
    fireEvent.mouseLeave(dropdownContainer)

    // Dropdown should still be visible immediately after mouse leave (due to delay)
    expect(screen.getByText('Peers')).toBeInTheDocument()

    // Wait for the delay to pass (150ms + some buffer)
    await new Promise(resolve => setTimeout(resolve, 200))

    // Dropdown should now be closed
    await waitFor(() => {
      expect(screen.queryByText('Peers')).not.toBeInTheDocument()
    })
  })

  test('dropdown stays open when re-entering before delay expires', async () => {
    renderWithRouter(<TopNav />)

    const accessControlButton = screen.getByText('Access Control').closest('button')
    const dropdownContainer = accessControlButton.parentElement

    // Open dropdown
    fireEvent.mouseEnter(dropdownContainer)
    await waitFor(() => {
      expect(screen.getByText('Peers')).toBeInTheDocument()
    })

    // Simulate mouse leave
    fireEvent.mouseLeave(dropdownContainer)

    // Before the timeout fires, re-enter
    await new Promise(resolve => setTimeout(resolve, 50))
    fireEvent.mouseEnter(dropdownContainer)

    // Wait past original timeout
    await new Promise(resolve => setTimeout(resolve, 200))

    // Dropdown should still be visible because we re-entered
    expect(screen.getByText('Peers')).toBeInTheDocument()
  })

  test('user dropdown opens on hover', async () => {
      renderWithRouter(<TopNav />)

      const username = screen.getByText('testuser')
      const userDropdownContainer = username.closest('div.relative')

      fireEvent.mouseEnter(userDropdownContainer)

      await waitFor(() => {
        expect(screen.getByText('Logout')).toBeInTheDocument()
      })
    })

  test('user dropdown closes with delay on mouse leave', async () => {
    renderWithRouter(<TopNav />)

    const username = screen.getByText('testuser')
    const userDropdownContainer = username.closest('div.relative')

    // Open dropdown
    fireEvent.mouseEnter(userDropdownContainer)
    await waitFor(() => {
      expect(screen.getByText('Logout')).toBeInTheDocument()
    })

    // Simulate mouse leave
    fireEvent.mouseLeave(userDropdownContainer)

    // Should still be visible immediately
    expect(screen.getByText('Logout')).toBeInTheDocument()

    // Wait for the delay to pass (150ms + some buffer)
    await new Promise(resolve => setTimeout(resolve, 200))

    // Should now be closed
    await waitFor(() => {
      expect(screen.queryByText('Logout')).not.toBeInTheDocument()
    })
  })

  test('hover behavior is disabled on mobile viewport', async () => {
    // Mock useIsMobile to return true (mobile viewport)
    mockIsMobile.mockReturnValue(true)

    renderWithRouter(<TopNav />)

    const userButton = screen.getByRole('button', { name: /testuser/ })
    const userDropdownContainer = userButton.closest('div.relative')

    // Simulate mouse enter on mobile
    fireEvent.mouseEnter(userDropdownContainer)

    // Wait a bit to ensure any potential state changes would have occurred
    await new Promise(resolve => setTimeout(resolve, 100))

    // Dropdown should NOT open on hover on mobile
    expect(screen.queryByText('Logout')).not.toBeInTheDocument()

    // Verify the button still exists and is clickable
    expect(userButton).toBeInTheDocument()

    // Reset mock for other tests
    mockIsMobile.mockReturnValue(false)
  })

  })

  describe('pending changes indicator', () => {
    test('renders Shield icon for Access Control', () => {
      renderWithRouter(<TopNav />)

      // The Access Control button should exist
      const accessControlButton = screen.getByText('Access Control').closest('button')
      expect(accessControlButton).toBeInTheDocument()
      // It should contain an SVG icon
      const icon = accessControlButton.querySelector('svg')
      expect(icon).toBeInTheDocument()
    })
  })

  describe('semantic structure', () => {
    test('header element is rendered', () => {
      const { container } = renderWithRouter(<TopNav />)

      const header = container.querySelector('header')
      expect(header).toBeInTheDocument()
    })

    test('navigation element has correct aria-label', () => {
      renderWithRouter(<TopNav />)

      const nav = screen.getByRole('navigation')
      expect(nav).toHaveAttribute('aria-label', 'Main navigation')
    })

    test('user menu button has accessible label', () => {
      renderWithRouter(<TopNav />)

      const userButton = screen.getByRole('button', { name: /user menu/i })
      expect(userButton).toBeInTheDocument()
    })
  })

  describe('branding', () => {
    test('renders Flame icon for logo', () => {
      const { container } = renderWithRouter(<TopNav />)

      // Find the Flame icon (it has a specific path for the flame)
      const header = container.querySelector('header')
      const flameIcon = header.querySelector('svg')
      expect(flameIcon).toBeInTheDocument()
    })

    test('brand text is rendered', () => {
      renderWithRouter(<TopNav />)

      const brandText = screen.getByText('RUNIC')
      expect(brandText).toBeInTheDocument()
    })
  })

  describe('responsive design', () => {
    test('desktop nav is rendered inside header', () => {
      const { container } = renderWithRouter(<TopNav />)

      const desktopNav = container.querySelector('header nav')
      expect(desktopNav).toBeInTheDocument()
    })

test('user dropdown button shows username', () => {
    renderWithRouter(<TopNav />)

      // The username span should be rendered
      const usernameSpan = screen.getByText('testuser')
      expect(usernameSpan).toBeInTheDocument()
    })

test('user dropdown shows username and version on mobile when opened', async () => {
    renderWithRouter(<TopNav />)

    // Find the user button
    const userButton = screen.getByRole('button', { name: /testuser/ })

    // Click to open dropdown (toggles userDropdownOpen state)
    fireEvent.click(userButton)

    // Wait for dropdown to open and version to load
    await waitFor(() => {
      // Logout button should appear in dropdown
      expect(screen.getByText('Logout')).toBeInTheDocument()
    })

    // Server Version should be visible in mobile dropdown
    await waitFor(() => {
      expect(screen.getByText(/Server Version:/)).toBeInTheDocument()
    })
  })
  })
})
