import '@testing-library/jest-dom'

// Mock IntersectionObserver (needed for components using scroll/visibility detection)
class MockIntersectionObserver {
  constructor(callback) {
    this.callback = callback
  }

  observe() {
    // No-op
  }

  unobserve() {
    // No-op
  }

  disconnect() {
    // No-op
  }

  // Helper method to trigger intersection changes in tests
  triggerIntersection(entries) {
    this.callback(entries, this)
  }
}

global.IntersectionObserver = MockIntersectionObserver

// Mock matchMedia (needed for responsive components)
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {}, // deprecated
    removeListener: () => {}, // deprecated
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => {},
  }),
})

// Mock ResizeObserver (needed for components using size detection)
class MockResizeObserver {
  constructor(callback) {
    this.callback = callback
  }

  observe() {
    // No-op
  }

  unobserve() {
    // No-op
  }

  disconnect() {
    // No-op
  }
}

global.ResizeObserver = MockResizeObserver

// Mock scrollTo for components that manipulate scroll position
window.scrollTo = () => {}

// Mock localStorage
const localStorageMock = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {},
  clear: () => {},
  length: 0,
  key: () => null,
}

Object.defineProperty(window, 'localStorage', {
  value: localStorageMock,
})

// Mock URL.createObjectURL and URL.revokeObjectURL (needed for file handling)
URL.createObjectURL = () => 'blob:mock-url'
URL.revokeObjectURL = () => {}
