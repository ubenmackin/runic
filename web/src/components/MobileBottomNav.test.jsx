import { render, screen, fireEvent, within } from '@testing-library/react'
import { describe, test, expect } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import MobileBottomNav from './MobileBottomNav'

// Helper to render with router
function renderWithRouter(ui, { route = '/' } = {}) {
  window.history.pushState({}, 'Test page', route)
  return render(ui, { wrapper: BrowserRouter })
}

describe('MobileBottomNav', () => {
  describe('rendering', () => {
    test('renders all navigation items', () => {
      renderWithRouter(<MobileBottomNav />)

      expect(screen.getByText('Dashboard')).toBeInTheDocument()
      expect(screen.getByText('Topology')).toBeInTheDocument()
      expect(screen.getByText('Access Control')).toBeInTheDocument()
      expect(screen.getByText('Logs')).toBeInTheDocument()
      expect(screen.getByText('Settings')).toBeInTheDocument()
    })

    test('renders as a nav element', () => {
      const { container } = renderWithRouter(<MobileBottomNav />)

      expect(container.querySelector('nav')).toBeInTheDocument()
    })

    test('navigation has correct aria-label', () => {
      renderWithRouter(<MobileBottomNav />)

      const nav = screen.getByRole('navigation')
      expect(nav).toHaveAttribute('aria-label', 'Mobile navigation')
    })
  })

  describe('navigation items without submenu', () => {
    test('Dashboard links to root', () => {
      renderWithRouter(<MobileBottomNav />)

      const dashboardLink = screen.getByText('Dashboard').closest('a')
      expect(dashboardLink).toHaveAttribute('href', '/')
    })

    test('Topology links to /topology', () => {
      renderWithRouter(<MobileBottomNav />)

      const topologyLink = screen.getByText('Topology').closest('a')
      expect(topologyLink).toHaveAttribute('href', '/topology')
    })

    test('Dashboard and Topology have accessible labels', () => {
      renderWithRouter(<MobileBottomNav />)

      expect(screen.getByLabelText('Dashboard')).toBeInTheDocument()
      expect(screen.getByLabelText('Topology')).toBeInTheDocument()
    })
  })

  describe('submenu toggle behavior', () => {
    test('first tap on Access Control opens submenu', () => {
      renderWithRouter(<MobileBottomNav />)

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      fireEvent.click(accessControlBtn)

      expect(screen.getByTestId('submenu-access-control')).toBeInTheDocument()
    })

    test('second tap on same submenu item closes submenu', () => {
      renderWithRouter(<MobileBottomNav />)

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      fireEvent.click(accessControlBtn)
      expect(screen.getByTestId('submenu-access-control')).toBeInTheDocument()

      fireEvent.click(accessControlBtn)
      expect(screen.queryByTestId('submenu-access-control')).not.toBeInTheDocument()
    })

    test('tapping different submenu item closes current and opens new', () => {
      renderWithRouter(<MobileBottomNav />)

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      fireEvent.click(accessControlBtn)
      expect(screen.getByTestId('submenu-access-control')).toBeInTheDocument()

      const logsBtn = screen.getByTestId('nav-item-logs')
      fireEvent.click(logsBtn)
      expect(screen.queryByTestId('submenu-access-control')).not.toBeInTheDocument()
      expect(screen.getByTestId('submenu-logs')).toBeInTheDocument()
    })

    test('clicking backdrop closes submenu', () => {
      renderWithRouter(<MobileBottomNav />)

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      fireEvent.click(accessControlBtn)
      expect(screen.getByTestId('submenu-access-control')).toBeInTheDocument()

      const backdrop = screen.getByTestId('submenu-backdrop')
      fireEvent.click(backdrop)
      expect(screen.queryByTestId('submenu-access-control')).not.toBeInTheDocument()
    })
  })

  describe('submenu navigation', () => {
    test('submenu items are rendered when submenu is open', () => {
      renderWithRouter(<MobileBottomNav />)

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      fireEvent.click(accessControlBtn)

      expect(screen.getByText('Peers')).toBeInTheDocument()
      expect(screen.getByText('Groups')).toBeInTheDocument()
      expect(screen.getByText('Services')).toBeInTheDocument()
      expect(screen.getByText('Policies')).toBeInTheDocument()
    })

    test('Logs submenu items are rendered when open', () => {
      renderWithRouter(<MobileBottomNav />)

      const logsBtn = screen.getByTestId('nav-item-logs')
      fireEvent.click(logsBtn)

      const logsSubmenu = screen.getByTestId('submenu-logs')
      expect(within(logsSubmenu).getByText('Logs')).toBeInTheDocument()
      expect(within(logsSubmenu).getByText('Alerts')).toBeInTheDocument()
    })

    test('Settings submenu items are rendered when open', () => {
      renderWithRouter(<MobileBottomNav />)

      const settingsBtn = screen.getByTestId('nav-item-settings')
      fireEvent.click(settingsBtn)

      const settingsSubmenu = screen.getByTestId('submenu-settings')
      expect(within(settingsSubmenu).getByText('Settings')).toBeInTheDocument()
      expect(within(settingsSubmenu).getByText('Setup Keys')).toBeInTheDocument()
      expect(within(settingsSubmenu).getByText('Users')).toBeInTheDocument()
    })

    test('submenu items are NavLink elements with proper href', () => {
      renderWithRouter(<MobileBottomNav />)

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      fireEvent.click(accessControlBtn)

      const peersLink = screen.getByTestId('submenu-item-peers')
      expect(peersLink.tagName).toBe('A')
      expect(peersLink).toHaveAttribute('href', '/peers')

      const groupsLink = screen.getByTestId('submenu-item-groups')
      expect(groupsLink).toHaveAttribute('href', '/groups')
    })
  })

  describe('active states', () => {
    test('highlights active Dashboard item on root route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/' })

      const dashboardLink = screen.getByText('Dashboard').closest('a')
      expect(dashboardLink).toHaveAttribute('aria-current', 'page')
    })

    test('highlights active Topology item on /topology route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/topology' })

      const topologyLink = screen.getByText('Topology').closest('a')
      expect(topologyLink).toHaveAttribute('aria-current', 'page')
    })

    test('highlights Access Control parent when on /peers route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/peers' })

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      expect(accessControlBtn).toHaveAttribute('data-active', 'true')
    })

    test('highlights Access Control parent when on /groups route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/groups' })

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      expect(accessControlBtn).toHaveAttribute('data-active', 'true')
    })

    test('highlights Access Control parent when on /services route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/services' })

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      expect(accessControlBtn).toHaveAttribute('data-active', 'true')
    })

    test('highlights Access Control parent when on /policies route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/policies' })

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      expect(accessControlBtn).toHaveAttribute('data-active', 'true')
    })

    test('highlights Logs parent when on /alerts route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/alerts' })

      const logsBtn = screen.getByTestId('nav-item-logs')
      expect(logsBtn).toHaveAttribute('data-active', 'true')
    })

    test('highlights Settings parent when on /setup-keys route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/setup-keys' })

      const settingsBtn = screen.getByTestId('nav-item-settings')
      expect(settingsBtn).toHaveAttribute('data-active', 'true')
    })

    test('highlights Settings parent when on /users route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/users' })

      const settingsBtn = screen.getByTestId('nav-item-settings')
      expect(settingsBtn).toHaveAttribute('data-active', 'true')
    })

    test('non-active items have default aria attributes', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/' })

      const topologyLink = screen.getByText('Topology').closest('a')
      expect(topologyLink).not.toHaveAttribute('aria-current')
    })

    test('submenu item shows active state when on matching route', async () => {
      renderWithRouter(<MobileBottomNav />, { route: '/peers' })

      // Open the Access Control submenu
      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      fireEvent.click(accessControlBtn)

      // The Peers submenu item should have aria-current (it's a NavLink)
      const peersItem = screen.getByTestId('submenu-item-peers')
      expect(peersItem).toHaveAttribute('aria-current', 'page')
    })
  })

  describe('semantic structure', () => {
    test('nav is rendered as navigation landmark', () => {
      const { container } = renderWithRouter(<MobileBottomNav />)

      const nav = container.querySelector('nav')
      expect(nav).toBeInTheDocument()
    })

    test('icons are present for all nav items', () => {
      const { container } = renderWithRouter(<MobileBottomNav />)

      // Each nav item should have an icon (svg)
      const nav = container.querySelector('nav')
      const icons = nav.querySelectorAll('svg')
      expect(icons.length).toBeGreaterThanOrEqual(5)
    })

    test('submenu buttons have chevron indicator', () => {
      renderWithRouter(<MobileBottomNav />)

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      // ChevronUp icon should be present
      expect(accessControlBtn.querySelector('svg')).toBeInTheDocument()
    })

	test('chevron rotates when submenu is open', () => {
			renderWithRouter(<MobileBottomNav />)

			const accessControlBtn = screen.getByTestId('nav-item-access-control')
			const chevron = accessControlBtn.querySelectorAll('svg')[1]

			fireEvent.click(accessControlBtn)
			expect(chevron.getAttribute('class')).toContain('rotate-180')
		})
  })

  describe('responsive behavior', () => {
    test('only one nav item is active at a time', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/topology' })

      const topologyLink = screen.getByText('Topology').closest('a')
      expect(topologyLink).toHaveAttribute('aria-current', 'page')

      // Other items should not have active styling
      const dashboardLink = screen.getByText('Dashboard').closest('a')
      expect(dashboardLink).not.toHaveAttribute('aria-current')
    })

    test('only one submenu can be open at a time', () => {
      renderWithRouter(<MobileBottomNav />)

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      fireEvent.click(accessControlBtn)
      expect(screen.getByTestId('submenu-access-control')).toBeInTheDocument()

      const settingsBtn = screen.getByTestId('nav-item-settings')
      fireEvent.click(settingsBtn)
      expect(screen.queryByTestId('submenu-access-control')).not.toBeInTheDocument()
      expect(screen.getByTestId('submenu-settings')).toBeInTheDocument()
    })
  })
})
