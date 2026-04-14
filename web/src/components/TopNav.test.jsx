import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import TopNav from './TopNav'
import { useAuthStore } from '../store'

// Mock useAuth hook
vi.mock('../hooks/useAuth', () => ({
  useAuth: () => ({
    isAdmin: useAuthStore.getState().role === 'admin',
  }),
}))

// Helper to render with router
function renderWithRouter(ui, { route = '/' } = {}) {
  window.history.pushState({}, 'Test page', route)
  return render(ui, { wrapper: BrowserRouter })
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

    test('renders mobile menu button', () => {
      renderWithRouter(<TopNav />)

      expect(screen.getByLabelText('Toggle menu')).toBeInTheDocument()
    })
  })

  describe('mobile menu', () => {
    test('opens mobile menu on button click', async () => {
      const user = userEvent.setup()
      renderWithRouter(<TopNav />)

      const menuButton = screen.getByLabelText('Toggle menu')
      await user.click(menuButton)

      // Mobile menu should show navigation items
      await waitFor(() => {
        expect(screen.getAllByText('Dashboard').length).toBeGreaterThan(1)
      })
    })

    test('shows all navigation items in mobile menu', async () => {
      const user = userEvent.setup()
      renderWithRouter(<TopNav />)

      const menuButton = screen.getByLabelText('Toggle menu')
      await user.click(menuButton)

      await waitFor(() => {
        expect(screen.getAllByText('Dashboard').length).toBeGreaterThan(1)
        expect(screen.getByText('Peers')).toBeInTheDocument()
        expect(screen.getByText('Groups')).toBeInTheDocument()
        expect(screen.getByText('Services')).toBeInTheDocument()
        expect(screen.getByText('Policies')).toBeInTheDocument()
        expect(screen.getAllByText('Logs').length).toBeGreaterThan(1)
        expect(screen.getByText('Alerts')).toBeInTheDocument()
      })
    })

    test('closes mobile menu when clicking overlay', async () => {
      const user = userEvent.setup()
      renderWithRouter(<TopNav />)

      const menuButton = screen.getByLabelText('Toggle menu')
      await user.click(menuButton)

      await waitFor(() => {
        expect(screen.getAllByText('Dashboard').length).toBeGreaterThan(1)
      })

      // Click the overlay
      const overlay = document.querySelector('.fixed.inset-0.bg-black\\/50')
      await user.click(overlay)

      await waitFor(() => {
        expect(screen.getAllByText('Dashboard').length).toBe(1)
      })
    })

    test('shows admin-only items in mobile menu for admin users', async () => {
      const user = userEvent.setup()
      useAuthStore.setState({ role: 'admin' })

      renderWithRouter(<TopNav />)

      const menuButton = screen.getByLabelText('Toggle menu')
      await user.click(menuButton)

      await waitFor(() => {
        expect(screen.getByText('Setup Keys')).toBeInTheDocument()
        expect(screen.getByText('Users')).toBeInTheDocument()
      })
    })

    test('hides admin-only items in mobile menu for non-admin users', async () => {
      const user = userEvent.setup()
      useAuthStore.setState({ role: 'viewer' })

      renderWithRouter(<TopNav />)

      const menuButton = screen.getByLabelText('Toggle menu')
      await user.click(menuButton)

      await waitFor(() => {
        expect(screen.getAllByText('Dashboard').length).toBeGreaterThan(1)
      })

      // Admin items should not be present
      expect(screen.queryByText('Setup Keys')).not.toBeInTheDocument()
      expect(screen.queryByText('Users')).not.toBeInTheDocument()
    })
  })

  describe('active states', () => {
    test('highlights active nav item', () => {
      renderWithRouter(<TopNav />, { route: '/topology' })

      // The Topology nav item should have active styling
      const topologyLink = screen.getByText('Topology').closest('a')
      expect(topologyLink.className).toContain('bg-')
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

    test('mobile menu button is visible on mobile only', () => {
      renderWithRouter(<TopNav />)

      const menuButton = screen.getByLabelText('Toggle menu')
      expect(menuButton).toHaveClass('md:hidden')
    })
  })
})
