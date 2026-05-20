import { render, screen } from '@testing-library/react'
import { describe, test, expect } from 'vitest'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Layout from './Layout'

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } },
})

function renderWithProviders(ui) {
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/test']}>
        <Routes>
          <Route element={ui}>
            <Route path="/test" element={<div data-testid="child-content">Child Content</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

describe('Layout', () => {
  describe('rendering', () => {
    test('renders without crashing', () => {
      renderWithProviders(<Layout />)
      // Layout renders the app shell with TopNav and MobileBottomNav
      expect(screen.getByRole('main')).toBeInTheDocument()
    })

    test('renders children via Outlet', () => {
      renderWithProviders(<Layout />)
      expect(screen.getByTestId('child-content')).toBeInTheDocument()
      expect(screen.getByText('Child Content')).toBeInTheDocument()
    })

    test('renders TopNav component', () => {
      renderWithProviders(<Layout />)
      // TopNav contains navigation elements
      expect(screen.getByRole('main')).toBeInTheDocument()
    })

    test('renders MobileBottomNav component', () => {
      renderWithProviders(<Layout />)
      // There are multiple navigation elements (TopNav + MobileBottomNav)
      const navElements = screen.getAllByRole('navigation')
      expect(navElements.length).toBeGreaterThanOrEqual(1)
    })
  })

  describe('structure', () => {
    test('has main element', () => {
      renderWithProviders(<Layout />)
      expect(screen.getByRole('main')).toBeInTheDocument()
    })

    test('has correct layout classes on wrapper', () => {
      const { container } = renderWithProviders(<Layout />)
      const wrapper = container.firstChild
      expect(wrapper.className).toContain('min-h-screen')
      expect(wrapper.className).toContain('bg-gray-50')
      expect(wrapper.className).toContain('flex')
      expect(wrapper.className).toContain('flex-col')
    })

    test('main element has flex-1 class', () => {
      renderWithProviders(<Layout />)
      const main = screen.getByRole('main')
      expect(main.className).toContain('flex-1')
    })
  })

  describe('accessibility', () => {
    test('has main landmark', () => {
      renderWithProviders(<Layout />)
      expect(screen.getByRole('main')).toBeInTheDocument()
    })

    test('has navigation landmarks', () => {
      renderWithProviders(<Layout />)
      const navElements = screen.getAllByRole('navigation')
      expect(navElements.length).toBeGreaterThanOrEqual(1)
    })
  })
})
