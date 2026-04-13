# Testing Guide

This document outlines the testing standards and best practices for the Runic web frontend. It covers how to run tests, write tests, and debug test failures.

## Table of Contents

- [Quick Start](#quick-start)
- [Test Setup](#test-setup)
- [Test Organization](#test-organization)
- [Writing Tests](#writing-tests)
- [Testing Patterns](#testing-patterns)
- [Mocking Strategies](#mocking-strategies)
- [Coverage Requirements](#coverage-requirements)
- [Debugging Tests](#debugging-tests)
- [Best Practices](#best-practices)

---

## Quick Start

### Running Tests

```bash
# Run tests in watch mode (development)
npm test

# Run all tests once (CI/pipeline)
npm run test:run

# Run tests with coverage report
npm run test:coverage

# Run tests with coverage and UI dashboard
npm run test:coverage:ui
```

### Common Commands

```bash
# Run specific test file
npm test -- path/to/file.test.js

# Run tests matching a pattern
npm test -- --grep "useDebounce"

# Run tests for a specific directory
npm test -- src/utils/

# Update snapshots
npm test -- -u
```

---

## Test Setup

### Configuration

Tests are configured in `vitest.config.js`:

```javascript
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.js'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      thresholds: {
        '**/utils/**': { branches: 70, functions: 70, lines: 70, statements: 70 },
        '**/components/**': { branches: 50, functions: 50, lines: 50, statements: 50 },
      },
    },
  },
})
```

### Test Environment

- **Environment**: `jsdom` - simulates a browser environment for testing React components
- **Globals**: `true` - Vitest globals (`describe`, `test`, `expect`, etc.) are available without imports
- **Setup File**: `./src/test/setup.js` - configures global mocks and testing utilities

### Setup File (`src/test/setup.js`)

The setup file provides global mocks for browser APIs:

```javascript
import '@testing-library/jest-dom'

// Mock IntersectionObserver (for scroll/visibility detection)
class MockIntersectionObserver { ... }
global.IntersectionObserver = MockIntersectionObserver

// Mock matchMedia (for responsive components)
Object.defineProperty(window, 'matchMedia', { ... })

// Mock ResizeObserver (for size detection)
class MockResizeObserver { ... }
global.ResizeObserver = MockResizeObserver

// Mock scrollTo
window.scrollTo = () => {}

// Mock localStorage
const localStorageMock = { ... }
Object.defineProperty(window, 'localStorage', { value: localStorageMock })

// Mock URL.createObjectURL/revokeObjectURL
URL.createObjectURL = () => 'blob:mock-url'
URL.revokeObjectURL = () => {}
```

---

## Test Organization

### File Naming

Test files should be placed alongside the code they test:

```
src/
├── utils/
│   ├── formatTime.js
│   ├── formatTime.test.js
│   ├── apiErrors.js
│   └── apiErrors.test.js
├── components/
│   ├── DataTable.jsx
│   ├── DataTable.test.jsx
│   ├── ToggleSwitch.jsx
│   └── ToggleSwitch.test.jsx
└── hooks/
    ├── useDebounce.js
    └── useDebounce.test.js
```

**Naming Convention**: `<filename>.test.{js,jsx,ts,tsx}`

### Test Structure

Organize tests using nested `describe` blocks:

```javascript
describe('functionName or ComponentName', () => {
  describe('category of behavior', () => {
    test('specific behavior description', () => {
      // test implementation
    })
  })
})
```

**Example from `apiErrors.test.js`:**

```javascript
describe('parseApiError', () => {
  describe('string errors', () => {
    test('returns string as-is', () => {
      expect(parseApiError('Something went wrong')).toBe('Something went wrong')
    })
  })

  describe('Error objects', () => {
    test('handles network errors (Failed to fetch)', () => {
      const error = new TypeError('Failed to fetch')
      error.name = 'TypeError'
      expect(parseApiError(error)).toBe('Unable to connect to server...')
    })
  })
})
```

---

## Writing Tests

### Importing Vitest Functions

While globals are enabled, you can optionally import for explicitness:

```javascript
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
```

### Basic Assertions

```javascript
// Equality
expect(value).toBe(expected)           // Strict equality (===)
expect(value).toEqual(expected)        // Deep equality
expect(value).toStrictEqual(expected)  // Strict deep equality

// Truthiness
expect(value).toBeTruthy()
expect(value).toBeFalsy()
expect(value).toBeNull()
expect(value).toBeUndefined()
expect(value).toBeDefined()

// Numbers
expect(value).toBeGreaterThan(5)
expect(value).toBeLessThanOrEqual(10)

// Strings
expect(value).toContain('substring')
expect(value).toMatch(/regex/)

// Arrays
expect(array).toHaveLength(3)
expect(array).toContain(item)
expect(array).toContainEqual({ id: 1 })

// Objects
expect(object).toHaveProperty('nested.key')
expect(object).toHaveProperty('key', value)

// Errors
expect(() => fn()).toThrow()
expect(() => fn()).toThrow('error message')

// Instances
expect(value).toBeInstanceOf(Promise)
expect(value).toBeInstanceOf(Error)
```

### Unit Tests for Utilities

Utility functions should have comprehensive tests covering:

1. **Happy path** - normal inputs
2. **Edge cases** - null, undefined, empty values
3. **Error cases** - invalid inputs

**Example from `formatTime.test.js`:**

```javascript
describe('formatRelativeTime', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2024-01-15T12:00:00Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  describe('handles invalid dates', () => {
    test('returns "Never" for null', () => {
      expect(formatRelativeTime(null)).toBe('Never')
    })
    test('returns "Never" for undefined', () => {
      expect(formatRelativeTime(undefined)).toBe('Never')
    })
  })

  describe('relative time formatting', () => {
    test('returns "Just now" for times less than 60 seconds ago', () => {
      const thirtySecondsAgo = new Date(mockNow.getTime() - 30 * 1000).toISOString()
      expect(formatRelativeTime(thirtySecondsAgo)).toBe('Just now')
    })
  })
})
```

### Component Tests with Testing Library

Use React Testing Library to test components from the user's perspective:

```javascript
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import MyComponent from './MyComponent'

describe('MyComponent', () => {
  test('renders correctly', () => {
    render(<MyComponent title="Test" />)
    expect(screen.getByText('Test')).toBeInTheDocument()
  })

  test('handles user interaction', async () => {
    const user = userEvent.setup()
    const handleClick = vi.fn()
    render(<MyComponent onClick={handleClick} />)

    await user.click(screen.getByRole('button'))
    expect(handleClick).toHaveBeenCalledTimes(1)
  })
})
```

**Key Queries (in order of preference):**

```javascript
// Accessible queries (preferred)
screen.getByRole('button', { name: /submit/i })
screen.getByLabelText('Email')
screen.getByPlaceholderText('Enter email')
screen.getByText('Welcome')

// Semantic queries
screen.getByAltText('Profile photo')

// Test IDs (last resort)
screen.getByTestId('submit-button')
```

### Hook Tests

Use `@testing-library/react`'s `renderHook` for testing hooks:

```javascript
import { renderHook, act } from '@testing-library/react'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { useDebounce } from './useDebounce'

describe('useDebounce', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  test('debounces rapid value changes', () => {
    const { result, rerender } = renderHook(
      ({ value, delay }) => useDebounce(value, delay),
      { initialProps: { value: 'first', delay: 500 } }
    )

    expect(result.current).toBe('first')

    rerender({ value: 'second', delay: 500 })
    rerender({ value: 'third', delay: 500 })

    act(() => {
      vi.advanceTimersByTime(500)
    })

    expect(result.current).toBe('third')
  })
})
```

### Testing Zustand Stores

When testing hooks that use Zustand stores:

```javascript
import { renderHook } from '@testing-library/react'
import { describe, test, expect, beforeEach, afterEach } from 'vitest'
import { useAuth } from './useAuth'
import { useAuthStore } from '../store'

describe('useAuth', () => {
  const originalState = useAuthStore.getState()

  beforeEach(() => {
    useAuthStore.setState({
      isAuthenticated: null,
      username: null,
      role: null,
    })
  })

  afterEach(() => {
    useAuthStore.setState(originalState)
  })

  test('returns correct role when user is authenticated', () => {
    useAuthStore.setState({
      isAuthenticated: true,
      username: 'testuser',
      role: 'admin',
    })

    const { result } = renderHook(() => useAuth())

    expect(result.current.role).toBe('admin')
    expect(result.current.isAdmin).toBe(true)
  })
})
```

---

## Testing Patterns

### Testing Props and State

```javascript
// Testing prop rendering
test('renders with custom className', () => {
  const { container } = render(<Button className="custom-class" />)
  expect(container.firstChild).toHaveClass('custom-class')
})

// Testing conditional rendering
test('does not render when loading', () => {
  const { container } = render(<Component loading={true} />)
  expect(container.firstChild).toBeNull()
})
```

### Testing User Interactions

```javascript
describe('button interactions', () => {
  test('calls onClick when clicked', async () => {
    const user = userEvent.setup()
    const handleClick = vi.fn()

    render(<Button onClick={handleClick} />)

    await user.click(screen.getByRole('button'))

    expect(handleClick).toHaveBeenCalledTimes(1)
  })

  test('can be activated with Enter key', async () => {
    const user = userEvent.setup()
    const handleClick = vi.fn()

    render(<Button onClick={handleClick} />)
    screen.getByRole('button').focus()

    await user.keyboard('{Enter}')

    expect(handleClick).toHaveBeenCalledTimes(1)
  })
})
```

### Testing Async Operations

```javascript
import { waitFor } from '@testing-library/react'

test('updates state after async operation', async () => {
  render(<Component />)

  await waitFor(() => {
    expect(screen.getByText('Loaded')).toBeInTheDocument()
  })
})
```

### Testing Event Handlers

```javascript
test('handles form submission', async () => {
  const user = userEvent.setup()
  const onSubmit = vi.fn()

  render(<Form onSubmit={onSubmit} />)

  await user.type(screen.getByLabelText('Name'), 'John')
  await user.click(screen.getByRole('button', { name: /submit/i }))

  expect(onSubmit).toHaveBeenCalledWith({ name: 'John' })
})
```

### Testing Accessibility

```javascript
describe('accessibility', () => {
  test('has correct role', () => {
    render(<ToggleSwitch checked={false} onChange={() => {}} />)
    expect(screen.getByRole('switch')).toBeInTheDocument()
  })

  test('has proper aria attributes', () => {
    render(<ToggleSwitch checked={true} onChange={() => {}} />)
    const toggle = screen.getByRole('switch')
    expect(toggle).toHaveAttribute('aria-checked', 'true')
  })

  test('has correct heading structure', () => {
    render(<ConfirmModal title="Important" message="Read this" onConfirm={() => {}} onCancel={() => {}} />)
    expect(screen.getByRole('heading', { level: 3 })).toHaveTextContent('Important')
  })
})
```

---

## Mocking Strategies

### vi.fn() - Mock Functions

Use for mocking callbacks and handlers:

```javascript
test('calls onChange with correct value', async () => {
  const user = userEvent.setup()
  const handleChange = vi.fn()

  render(<ToggleSwitch checked={false} onChange={handleChange} />)

  await user.click(screen.getByRole('switch'))

  expect(handleChange).toHaveBeenCalledWith(true)
  expect(handleChange).toHaveBeenCalledTimes(1)
})
```

### vi.mock() - Module Mocking

Use for mocking entire modules:

```javascript
// Mock a module
vi.mock('./api', () => ({
  fetchData: vi.fn(() => Promise.resolve({ data: [] })),
}))

// Mock with implementation
vi.mock('./utils', () => ({
  formatDate: vi.fn((date) => 'formatted date'),
}))
```

### vi.useFakeTimers() - Timer Mocking

Use for testing debounces, throttles, and timeouts:

```javascript
describe('debounced function', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  test('debounces calls', () => {
    const { result, rerender } = renderHook(
      ({ value }) => useDebounce(value, 500),
      { initialProps: { value: 'initial' } }
    )

    rerender({ value: 'updated' })

    act(() => {
      vi.advanceTimersByTime(500)
    })

    expect(result.current).toBe('updated')
  })
})
```

### Mocking Fetch/API Calls

**Using vi.fn() for fetch mocking:**

```javascript
describe('API Client', () => {
  let mockFetch

  beforeEach(() => {
    vi.resetModules()
    mockFetch = vi.fn()
    global.fetch = mockFetch
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  test('makes correct request', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ data: { id: 1 } }),
    })

    await api.get('/endpoint')

    expect(mockFetch).toHaveBeenCalledWith(
      '/api/v1/endpoint',
      expect.objectContaining({ method: 'GET' })
    )
  })
})
```

### Mocking Browser APIs

Global mocks are set up in `src/test/setup.js`. For test-specific mocks:

```javascript
test('uses IntersectionObserver', () => {
  const observe = vi.fn()
  const unobserve = vi.fn()

  class MockObserver {
    observe = observe
    unobserve = unobserve
  }

  global.IntersectionObserver = MockObserver

  render(<LazyComponent />)

  expect(observe).toHaveBeenCalled()
})
```

### MSW (Mock Service Worker)

For integration tests with API mocking, MSW is available:

```javascript
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'

const server = setupServer(
  http.get('/api/v1/data', () => {
    return HttpResponse.json({ data: { id: 1, name: 'Test' } })
  })
)

beforeAll(() => server.listen())
afterEach(() => server.resetHandlers())
afterAll(() => server.close())
```

---

## Coverage Requirements

### Thresholds

Coverage thresholds are configured per directory:

| Directory | Branches | Functions | Lines | Statements |
|-----------|----------|-----------|-------|------------|
| `**/utils/**` | 70% | 70% | 70% | 70% |
| `**/components/**` | 50% | 50% | 50% | 50% |

### Running Coverage

```bash
# Generate coverage report
npm run test:coverage

# Coverage with UI dashboard
npm run test:coverage:ui
```

### Coverage Report Locations

- **Text output**: Terminal
- **JSON report**: `coverage/coverage-final.json`
- **HTML report**: `coverage/index.html` (open in browser)

### Writing Tests for Coverage

Focus on:

1. **Branch coverage** - Test all conditional paths (if/else, switch)
2. **Function coverage** - Ensure all exported functions are tested
3. **Line coverage** - Cover all executable lines

**Example ensuring branch coverage:**

```javascript
describe('isRecoverableError', () => {
  // Test true branches
  test('network errors are recoverable', () => {
    const error = new TypeError('Failed to fetch')
    expect(isRecoverableError(error)).toBe(true)
  })

  // Test false branches
  test('401 errors are NOT recoverable', () => {
    const response = new Response(null, { status: 401 })
    expect(isRecoverableError(response)).toBe(false)
  })
})
```

---

## Debugging Tests

### Using screen.debug()

```javascript
import { screen } from '@testing-library/react'

test('debugging example', () => {
  render(<Component />)

  // Print the entire DOM
  screen.debug()

  // Print specific element
  screen.debug(screen.getByRole('button'))

  // Print with highlight
  screen.logTestingPlaygroundURL()
})
```

### Using console.log

```javascript
test('debugging with console', () => {
  const result = myFunction(input)
  console.log('Result:', result)
  console.log('Type:', typeof result)
  expect(result).toBe(expected)
})
```

### Running Single Tests

```bash
# Run specific test file in watch mode
npm test -- formatTime.test.js

# Run tests matching a pattern
npm test -- --grep "formatRelativeTime"

# Run with verbose output
npm test -- --reporter=verbose
```

### Common Issues and Solutions

**Element not found:**
```javascript
// Problem: getByText fails
// Solution: Use more flexible queries
screen.getByText(/partial text/i)
screen.getByRole('button', { name: /submit/i })

// Or check if element exists first
expect(screen.queryByText('Text')).not.toBeInTheDocument()
```

**Async timing issues:**
```javascript
// Problem: Test passes before async completes
// Solution: Use waitFor or findBy
import { waitFor } from '@testing-library/react'

await waitFor(() => {
  expect(screen.getByText('Loaded')).toBeInTheDocument()
})

// Or use findBy (combines query + waitFor)
const element = await screen.findByText('Loaded')
```

**Act warnings:**
```javascript
// Problem: "Warning: An update to Component was not wrapped in act()"
// Solution: Wrap state updates in act()
import { act } from '@testing-library/react'

act(() => {
  vi.advanceTimersByTime(500)
})
```

**Mock not working:**
```javascript
// Problem: Mock not being called or returning wrong value
// Solution: Check mock setup and reset
beforeEach(() => {
  vi.resetModules() // Reset module cache
  vi.clearAllMocks() // Clear mock call history
})
```

---

## Best Practices

### DO

✅ **Test behavior, not implementation**

```javascript
// Good - tests what user sees
expect(screen.getByText('Welcome')).toBeInTheDocument()

// Avoid - tests implementation details
expect(component.state.loading).toBe(false)
```

✅ **Use descriptive test names**

```javascript
// Good
test('displays error message when email is invalid', () => {})

// Avoid
test('works', () => {})
```

✅ **Organize with describe blocks**

```javascript
describe('ComponentName', () => {
  describe('rendering', () => {
    test('renders correctly', () => {})
  })

  describe('interactions', () => {
    test('handles click', () => {})
  })
})
```

✅ **Test edge cases**

```javascript
describe('edge cases', () => {
  test('handles null input', () => {
    expect(parseValue(null)).toBe('')
  })

  test('handles empty array', () => {
    expect(aggregate([])).toBe(0)
  })

  test('handles very large numbers', () => {
    expect(summarize(1000000)).toBeDefined()
  })
})
```

✅ **Use beforeEach/afterEach for setup**

```javascript
describe('with mock timers', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  test('debounces correctly', () => {
    // test implementation
  })
})
```

✅ **Keep tests isolated**

```javascript
// Good - each test is independent
beforeEach(() => {
  vi.clearAllMocks()
})

test('test 1', () => {
  // Doesn't affect test 2
})

test('test 2', () => {
  // Fresh state
})
```

### DON'T

❌ **Test implementation details**

```javascript
// Avoid - coupled to implementation
expect(componentRef.current.state.count).toBe(5)

// Better - test behavior
expect(screen.getByText('Count: 5')).toBeInTheDocument()
```

❌ **Use arbitrary timeouts**

```javascript
// Avoid
await new Promise(resolve => setTimeout(resolve, 100))

// Better
await waitFor(() => {
  expect(screen.getByText('Loaded')).toBeInTheDocument()
})
```

❌ **Share state between tests**

```javascript
// Avoid
let sharedState
test('test 1', () => {
  sharedState = 'modified'
})
test('test 2', () => {
  // Depends on test 1's execution order
})

// Better - each test is independent
test('test 1', () => {
  const localState = 'value'
})
test('test 2', () => {
  // Fresh state
})
```

❌ **Skip tests without reason**

```javascript
// Avoid
test.skip('broken test', () => {})

// If you must skip, add a reason
// TODO: Fix this test after API update
test.skip('temporarily disabled - waiting for API fix', () => {})
```

❌ **Over-mock**

```javascript
// Avoid - mocks everything
vi.mock('react', () => ({
  useState: vi.fn(),
  useEffect: vi.fn(),
}))

// Better - mock only what's necessary
vi.mock('./api', () => ({
  fetchData: vi.fn(),
}))
```

### Test File Examples

Refer to existing test files for patterns:

| Type | Example File | Key Patterns |
|------|--------------|--------------|
| Utility | `src/utils/formatTime.test.js` | Timer mocking, edge cases |
| Utility | `src/utils/apiErrors.test.js` | Comprehensive coverage, nested describes |
| Component | `src/components/DataTable.test.jsx` | Props, events, accessibility |
| Component | `src/components/ConfirmModal.test.jsx` | Portals, focus trap, keyboard |
| Hook | `src/hooks/useDebounce.test.js` | renderHook, fake timers |
| Hook | `src/hooks/useFocusTrap.test.js` | DOM setup/teardown, spies |
| API | `src/api/client.test.js` | Fetch mocking, async handling |

---

## Quick Reference

### Imports

```javascript
// Vitest
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

// React Testing Library
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderHook } from '@testing-library/react'
```

### Common Patterns

```javascript
// Render component
render(<Component prop="value" />)

// Find element
const button = screen.getByRole('button', { name: /submit/i })

// Interact
const user = userEvent.setup()
await user.click(button)

// Assert
expect(button).toBeInTheDocument()
expect(handleClick).toHaveBeenCalled()
```

### Mock Patterns

```javascript
// Mock function
const handler = vi.fn()

// Mock implementation
const mock = vi.fn(() => 'value')

// Mock return value
mock.mockReturnValue('value')
mock.mockReturnValueOnce('first')

// Mock resolved value (promises)
mock.mockResolvedValue({ data: [] })
mock.mockResolvedValueOnce({ data: [] })

// Spy on method
const spy = vi.spyOn(object, 'method')

// Fake timers
vi.useFakeTimers()
vi.advanceTimersByTime(1000)
vi.useRealTimers()
```

---

For more information, see:
- [Vitest Documentation](https://vitest.dev/)
- [React Testing Library](https://testing-library.com/docs/react-testing-library/intro/)
- [Testing Library Jest-DOM](https://github.com/testing-library/jest-dom)
