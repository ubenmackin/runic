import { render, screen } from '@testing-library/react'
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
  })

  describe('navigation items', () => {
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

    test('Access Control links to /peers', () => {
      renderWithRouter(<MobileBottomNav />)

      const accessControlLink = screen.getByText('Access Control').closest('a')
      expect(accessControlLink).toHaveAttribute('href', '/peers')
    })

    test('Logs links to /logs', () => {
      renderWithRouter(<MobileBottomNav />)

      const logsLink = screen.getByText('Logs').closest('a')
      expect(logsLink).toHaveAttribute('href', '/logs')
    })

    test('Settings links to /settings', () => {
      renderWithRouter(<MobileBottomNav />)

      const settingsLink = screen.getByText('Settings').closest('a')
      expect(settingsLink).toHaveAttribute('href', '/settings')
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

    test('highlights active Access Control item on /peers route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/peers' })

      const accessControlLink = screen.getByText('Access Control').closest('a')
      expect(accessControlLink.className).toContain('text-purple-active')
    })

    test('highlights active Logs item on /logs route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/logs' })

      const logsLink = screen.getByText('Logs').closest('a')
      expect(logsLink.className).toContain('text-purple-active')
    })

    test('highlights active Settings item on /settings route', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/settings' })

      const settingsLink = screen.getByText('Settings').closest('a')
      expect(settingsLink.className).toContain('text-purple-active')
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
      expect(icons.length).toBe(5)
    })
  })

  describe('responsive behavior', () => {
    test('only one nav item is active at a time', () => {
      renderWithRouter(<MobileBottomNav />, { route: '/topology' })

      const activeItems = screen.getAllByText('Topology')
      // Only the nav item should have active styling
      const navItem = activeItems.find(el => el.closest('a')?.className.includes('text-purple-active'))
      expect(navItem).toBeInTheDocument()

      // Other items should not have active styling
      const dashboardLink = screen.getByText('Dashboard').closest('a')
      expect(dashboardLink.className).not.toContain('text-purple-active')
    })
  })
})
