import { render } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import { vi } from 'vitest'

/**
 * Creates a test QueryClient with disabled retries for predictable test behavior.
 * @returns {QueryClient}
 */
export function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  })
}

/**
 * Renders a component with all required providers for testing.
 * @param {React.ReactElement} ui - Component to render
 * @param {Object} options - Options object
 * @param {string} options.route - Initial route (default: '/')
 * @param {QueryClient} options.queryClient - Optional custom QueryClient
 * @returns {Object} RTL render result with queryClient
 */
export function renderWithProviders(ui, { route = '/', queryClient } = {}) {
  window.history.pushState({}, 'Test page', route)
  const client = queryClient || createTestQueryClient()
  return {
    ...render(ui, {
      wrapper: ({ children }) => (
        <QueryClientProvider client={client}>
          <BrowserRouter>{children}</BrowserRouter>
        </QueryClientProvider>
      ),
    }),
    queryClient: client,
  }
}

/**
 * Creates a wrapper component with providers for use with @testing-library/react's render.
 * @param {QueryClient} queryClient - Optional custom QueryClient
 * @returns {Function} Wrapper component
 */
export function createProvidersWrapper(queryClient = null) {
  const client = queryClient || createTestQueryClient()
  return function Wrapper({ children }) {
    return (
      <QueryClientProvider client={client}>
        <BrowserRouter>{children}</BrowserRouter>
      </QueryClientProvider>
    )
  }
}

/**
 * Mock implementation for useIsMobile hook.
 * @param {boolean} isMobile - Whether to simulate mobile view
 */
export function mockUseIsMobile(isMobile = false) {
  vi.mock('../hooks/useIsMobile', () => ({
    useIsMobile: () => isMobile,
  }))
}