import { render, screen, fireEvent, within } from '@testing-library/react'
import { describe, test, expect, beforeEach } from 'vitest'
import { BrowserRouter, useLocation } from 'react-router-dom'
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
  })

  describe('active states', () => {
    test('highlights active Dashboard item on root route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/' })

      const dashboardLink = screen.getByText('Dashboard').closest('a')
      expect(dashboardLink.className).toContain('text-purple-active')
    })

    test('highlights active Topology item on /topology route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/topology' })

      const topologyLink = screen.getByText('Topology').closest('a')
      expect(topologyLink.className).toContain('text-purple-active')
    })

    test('highlights Access Control parent when on /peers route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/peers' })

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      expect(accessControlBtn.className).toContain('text-purple-active')
    })

    test('highlights Access Control parent when on /groups route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/groups' })

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      expect(accessControlBtn.className).toContain('text-purple-active')
    })

    test('highlights Access Control parent when on /services route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/services' })

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      expect(accessControlBtn.className).toContain('text-purple-active')
    })

    test('highlights Access Control parent when on /policies route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/policies' })

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      expect(accessControlBtn.className).toContain('text-purple-active')
    })

    test('highlights Logs parent when on /alerts route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/alerts' })

      const logsBtn = screen.getByTestId('nav-item-logs')
      expect(logsBtn.className).toContain('text-purple-active')
    })

    test('highlights Settings parent when on /setup-keys route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/setup-keys' })

      const settingsBtn = screen.getByTestId('nav-item-settings')
      expect(settingsBtn.className).toContain('text-purple-active')
    })

    test('highlights Settings parent when on /users route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/users' })

      const settingsBtn = screen.getByTestId('nav-item-settings')
      expect(settingsBtn.className).toContain('text-purple-active')
    })

    test('non-active items have default styling', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/' })

      const topologyLink = screen.getByText('Topology').closest('a')
      expect(topologyLink.className).toContain('text-gray-400')
    })
  })

  describe('styling', () => {
    test('nav is fixed at bottom', () => {
      const { container } = renderWithRouter(<MobileBottomNav />)

      const nav = container.querySelector('nav')
      expect(nav.className).toContain('fixed')
      expect(nav.className).toContain('bottom-0')
      expect(nav.className).toContain('left-0')
      expect(nav.className).toContain('right-0')
    })

    test('nav has correct height', () => {
      const { container } = renderWithRouter(<MobileBottomNav />)

      const nav = container.querySelector('nav')
      expect(nav.className).toContain('h-16')
    })

    test('nav has dark background', () => {
      const { container } = renderWithRouter(<MobileBottomNav />)

      const nav = container.querySelector('nav')
      expect(nav.className).toContain('bg-charcoal-dark')
    })

    test('nav has top border', () => {
      const { container } = renderWithRouter(<MobileBottomNav />)

      const nav = container.querySelector('nav')
      expect(nav.className).toContain('border-t')
      expect(nav.className).toContain('border-gray-border')
    })

    test('nav is hidden on desktop (md breakpoint and up)', () => {
      const { container } = renderWithRouter(<MobileBottomNav />)

      const nav = container.querySelector('nav')
      expect(nav.className).toContain('md:hidden')
    })

    test('nav items are arranged horizontally', () => {
      const { container } = renderWithRouter(<MobileBottomNav />)

      const innerDiv = container.querySelector('nav > div')
      expect(innerDiv.className).toContain('flex')
      expect(innerDiv.className).toContain('justify-around')
    })

    test('nav items have column layout', () => {
      renderWithRouter(<MobileBottomNav />)

      const dashboardLink = screen.getByText('Dashboard').closest('a')
      expect(dashboardLink.className).toContain('flex-col')
    })

    test('submenu popup appears above nav bar', () => {
      renderWithRouter(<MobileBottomNav />)

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      fireEvent.click(accessControlBtn)

      const submenu = screen.getByTestId('submenu-access-control')
      expect(submenu.className).toContain('bottom-full')
      expect(submenu.className).toContain('mb-2')
    })

    test('submenu popup has rounded corners', () => {
      renderWithRouter(<MobileBottomNav />)

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      fireEvent.click(accessControlBtn)

      const submenu = screen.getByTestId('submenu-access-control')
      expect(submenu.className).toContain('rounded-lg')
    })

    test('backdrop overlay is visible when submenu is open', () => {
      renderWithRouter(<MobileBottomNav />)

      const accessControlBtn = screen.getByTestId('nav-item-access-control')
      fireEvent.click(accessControlBtn)

      const backdrop = screen.getByTestId('submenu-backdrop')
      expect(backdrop.className).toContain('bg-black/50')
    })
  })

  describe('accessibility', () => {
    test('nav items are focusable', () => {
      renderWithRouter(<MobileBottomNav />)

      const dashboardLink = screen.getByText('Dashboard').closest('a')
      expect(dashboardLink).toBeInTheDocument()
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
			expect(chevron.getAttribute('class')).not.toContain('rotate-180')

			fireEvent.click(accessControlBtn)
			expect(chevron.getAttribute('class')).toContain('rotate-180')
		})
  })

  describe('responsive behavior', () => {
    test('only one nav item is active at a time', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/topology' })

      const topologyLink = screen.getByText('Topology').closest('a')
      expect(topologyLink.className).toContain('text-purple-active')

      // Other items should not have active styling
      const dashboardLink = screen.getByText('Dashboard').closest('a')
      expect(dashboardLink.className).not.toContain('text-purple-active')
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
