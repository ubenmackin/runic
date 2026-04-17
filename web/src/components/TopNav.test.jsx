import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
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
    test('highlights active nav item with purple styling', () => {
      renderWithRouter(<TopNav />, { route: '/topology' })

      // The Topology nav item should have purple active styling
      const topologyLink = screen.getByText('Topology').closest('a')
      expect(topologyLink.className).toContain('bg-purple-active')
      expect(topologyLink.className).toContain('text-purple-active')
      expect(topologyLink.className).toContain('border-purple-active')
    })

    test('highlights Dashboard as active on root route', () => {
      renderWithRouter(<TopNav />, { route: '/' })

      const dashboardLink = screen.getByText('Dashboard').closest('a')
      expect(dashboardLink.className).toContain('bg-purple-active')
      expect(dashboardLink.className).toContain('text-purple-active')
      expect(dashboardLink.className).toContain('border-purple-active')
    })

    test('inactive nav items have default styling', () => {
      renderWithRouter(<TopNav />, { route: '/topology' })

      // Dashboard should be inactive
      const dashboardLink = screen.getByText('Dashboard').closest('a')
      expect(dashboardLink.className).toContain('text-slate-500')
      expect(dashboardLink.className).toContain('border-transparent')
    })
  })

  describe('parent menu highlighting', () => {
    test('highlights Access Control parent when child route is active', () => {
      renderWithRouter(<TopNav />, { route: '/peers' })

      // Access Control button should show active styling
      const accessControlButton = screen.getByText('Access Control').closest('button')
      expect(accessControlButton.className).toContain('bg-purple-active')
      expect(accessControlButton.className).toContain('text-purple-active')
      expect(accessControlButton.className).toContain('border-purple-active')
    })

    test('highlights Access Control parent for /groups route', () => {
      renderWithRouter(<TopNav />, { route: '/groups' })

      const accessControlButton = screen.getByText('Access Control').closest('button')
      expect(accessControlButton.className).toContain('bg-purple-active')
    })

    test('highlights Access Control parent for /services route', () => {
      renderWithRouter(<TopNav />, { route: '/services' })

      const accessControlButton = screen.getByText('Access Control').closest('button')
      expect(accessControlButton.className).toContain('bg-purple-active')
    })

    test('highlights Access Control parent for /policies route', () => {
      renderWithRouter(<TopNav />, { route: '/policies' })

      const accessControlButton = screen.getByText('Access Control').closest('button')
      expect(accessControlButton.className).toContain('bg-purple-active')
    })

    test('highlights Logs parent when /logs route is active', () => {
      renderWithRouter(<TopNav />, { route: '/logs' })

      const logsButton = screen.getByText('Logs').closest('button')
      expect(logsButton.className).toContain('bg-purple-active')
      expect(logsButton.className).toContain('text-purple-active')
    })

    test('highlights Logs parent when /alerts route is active', () => {
      renderWithRouter(<TopNav />, { route: '/alerts' })

      const logsButton = screen.getByText('Logs').closest('button')
      expect(logsButton.className).toContain('bg-purple-active')
    })

    test('highlights Settings parent when /setup-keys route is active', () => {
      renderWithRouter(<TopNav />, { route: '/setup-keys' })

      const settingsButton = screen.getByText('Settings').closest('button')
      expect(settingsButton.className).toContain('bg-purple-active')
    })

    test('highlights Settings parent when /users route is active', () => {
      renderWithRouter(<TopNav />, { route: '/users' })

      const settingsButton = screen.getByText('Settings').closest('button')
      expect(settingsButton.className).toContain('bg-purple-active')
    })

    test('highlights Settings parent when /settings route is active', () => {
      renderWithRouter(<TopNav />, { route: '/settings' })

      const settingsButton = screen.getByText('Settings').closest('button')
      expect(settingsButton.className).toContain('bg-purple-active')
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
    expect(peersLink.className).toContain('bg-purple-active')
    expect(peersLink.className).toContain('text-purple-active')
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
})

  describe('pending changes indicator', () => {
    test('shows regular Shield icon when no pending changes', () => {
      renderWithRouter(<TopNav />)

      // The Shield icon should be rendered without orange color
      const accessControlButton = screen.getByText('Access Control').closest('button')
      const icon = accessControlButton.querySelector('svg')
      expect(icon.className).not.toContain('text-orange-500')
    })
  })

  describe('styling', () => {
    test('header has correct height', () => {
      const { container } = renderWithRouter(<TopNav />)

      const header = container.querySelector('header')
      expect(header.className).toContain('h-[52px]')
    })

    test('header is sticky at top', () => {
      const { container } = renderWithRouter(<TopNav />)

      const header = container.querySelector('header')
      expect(header.className).toContain('sticky')
      expect(header.className).toContain('top-0')
    })

    test('has correct z-index for fixed positioning', () => {
      const { container } = renderWithRouter(<TopNav />)

      const header = container.querySelector('header')
      expect(header.className).toContain('z-40')
    })

    test('nav items use rounded-none class', () => {
      const { container } = renderWithRouter(<TopNav />)

      // Check that nav items have rounded-none
      const navItems = container.querySelectorAll('nav a')
      navItems.forEach(item => {
        expect(item.className).toContain('rounded-none')
      })
    })

    test('buttons in dropdowns use rounded-none class', () => {
      const { container } = renderWithRouter(<TopNav />)

      // Find all buttons in the nav
      const buttons = container.querySelectorAll('nav button')
      buttons.forEach(button => {
        expect(button.className).toContain('rounded-none')
      })
    })

    test('header has border', () => {
      const { container } = renderWithRouter(<TopNav />)

      const header = container.querySelector('header')
      expect(header.className).toContain('border-b')
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

    test('brand text has correct styling', () => {
      renderWithRouter(<TopNav />)

      const brandText = screen.getByText('RUNIC')
      expect(brandText.className).toContain('text-xl')
      expect(brandText.className).toContain('font-bold')
    })
  })

  describe('responsive design', () => {
    test('desktop nav is hidden on mobile', () => {
      const { container } = renderWithRouter(<TopNav />)

      const desktopNav = container.querySelector('nav.hidden.md\\:flex')
      expect(desktopNav).toBeInTheDocument()
    })

    test('user dropdown button shows icon only on mobile', () => {
      const { container } = renderWithRouter(<TopNav />)

      // The username span should be hidden on mobile
      const usernameSpan = screen.getByText('testuser')
      expect(usernameSpan).toHaveClass('hidden')
      expect(usernameSpan).toHaveClass('md:inline')
    })

    test('user dropdown shows username and version on mobile when opened', async () => {
      const user = userEvent.setup()
      const { container } = renderWithRouter(<TopNav />)

      // Find the user button (it contains the User icon and chevron)
      const userButtons = container.querySelectorAll('header button')
      // The user dropdown button is the last one in the header
      const userButton = Array.from(userButtons).find(btn =>
        btn.querySelector('svg') && btn.closest('.relative')
      )
      await user.click(userButton)

      await waitFor(() => {
        // Username should appear in mobile dropdown (bold)
        expect(screen.getAllByText('testuser').length).toBeGreaterThan(0)
        // Server Version should be visible
        expect(screen.getByText(/Server Version:/)).toBeInTheDocument()
      })
    })
  })
})
