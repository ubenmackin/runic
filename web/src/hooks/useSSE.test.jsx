import { renderHook, act } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { useSSE } from './useSSE'

// --- Mock EventSource ---
class MockEventSource {
  static instances = []
  static last() {
    return MockEventSource.instances[MockEventSource.instances.length - 1]
  }
  static reset() {
    MockEventSource.instances = []
  }

  // EventSource readyState constants
  static CONNECTING = 0
  static OPEN = 1
  static CLOSED = 2

  constructor(url, opts) {
    this.url = url
    this.opts = opts
    this.readyState = 0 // CONNECTING
    this.onerror = null
    this._listeners = {}
    MockEventSource.instances.push(this)
  }

  addEventListener(type, handler) {
    if (!this._listeners[type]) {
      this._listeners[type] = []
    }
    this._listeners[type].push(handler)
  }

  close() {
    this.readyState = 2 // CLOSED
  }

  // Test helpers
  simulateOpen() {
    this.readyState = 1 // OPEN
    const handlers = this._listeners['open'] || []
    handlers.forEach((h) => h())
  }

  simulateEvent(type, data, lastEventId = null) {
    const handlers = this._listeners[type] || []
    const event = { data: typeof data === 'string' ? data : JSON.stringify(data), lastEventId }
    handlers.forEach((h) => h(event))
  }

  simulateCloseError() {
    this.readyState = 2 // CLOSED
    // The hook assigns to es.onerror, so dispatch that handler
    if (typeof this.onerror === 'function') {
      this.onerror()
    }
    // Also dispatch any listeners registered via addEventListener('error', ...)
    const handlers = this._listeners['error'] || []
    handlers.forEach((h) => h())
  }
}

// Replace global EventSource with mock
let originalEventSource

beforeEach(() => {
  originalEventSource = global.EventSource
  global.EventSource = MockEventSource
  MockEventSource.reset()
})

afterEach(() => {
  global.EventSource = originalEventSource
})

// --- QueryClient wrapper ---
function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  })
  return function Wrapper({ children }) {
    return (
      <QueryClientProvider client={queryClient}>
        {children}
      </QueryClientProvider>
    )
  }
}

describe('useSSE', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  test('does not connect when enabled is false', () => {
    renderHook(() => useSSE({ enabled: false }), {
      wrapper: createWrapper(),
    })

    expect(MockEventSource.instances).toHaveLength(0)
  })

  test('connects when enabled is true', () => {
    renderHook(() => useSSE({ enabled: true }), {
      wrapper: createWrapper(),
    })

    expect(MockEventSource.instances).toHaveLength(1)
    const es = MockEventSource.last()
    expect(es.url).toContain('/api/v1/events')
    expect(es.url).not.toContain('lastEventId')
    expect(es.opts).toEqual({ withCredentials: true })
  })

  test('cleans up EventSource on unmount', () => {
    const { unmount } = renderHook(() => useSSE(), {
      wrapper: createWrapper(),
    })

    const es = MockEventSource.last()
    expect(es.readyState).not.toBe(2)

    unmount()

    expect(es.readyState).toBe(2)
  })

  test('cleans up reconnect timeout on unmount', () => {
    const { unmount } = renderHook(() => useSSE(), {
      wrapper: createWrapper(),
    })

    // Trigger a closed error to schedule a reconnect
    act(() => {
      MockEventSource.last().simulateCloseError()
    })

    // Unmount should clear the reconnect timeout
    unmount()

    // Advance timers — no reconnect should happen after unmount
    act(() => {
      vi.advanceTimersByTime(30000)
    })

    // Only the original EventSource should exist (no reconnect)
    expect(MockEventSource.instances).toHaveLength(1)
  })

  test('clears reconnect timeout when enabled toggles to false', () => {
    const { rerender } = renderHook(
      ({ enabled }) => useSSE({ enabled }),
      {
        initialProps: { enabled: true },
        wrapper: createWrapper(),
      }
    )

    // Trigger a closed error to schedule a reconnect
    act(() => {
      MockEventSource.last().simulateCloseError()
    })

    // Toggle enabled to false — should clear the reconnect timeout
    rerender({ enabled: false })

    // Advance timers — no reconnect should happen
    act(() => {
      vi.advanceTimersByTime(30000)
    })

    // Only the original EventSource should exist (no reconnect)
    expect(MockEventSource.instances).toHaveLength(1)
  })

  test('stops reconnecting after MAX_RECONNECT_ATTEMPTS', () => {
    renderHook(() => useSSE(), {
      wrapper: createWrapper(),
    })

    // Simulate failed connection cycles to exhaust MAX_RECONNECT_ATTEMPTS (10).
    // Each cycle: error on current ES -> scheduleReconnect (attempts++) ->
    // timeout -> connect (new ES). After 10 scheduleReconnect calls the counter
    // reaches 10, and the 11th error triggers scheduleReconnect which sees
    // attempts >= MAX and stops.
    for (let i = 0; i < 11; i++) {
      act(() => {
        MockEventSource.last().simulateCloseError()
      })
      act(() => {
        vi.advanceTimersByTime(30000)
      })
    }

    // After max attempts, no more EventSources should be created
    const instanceCount = MockEventSource.instances.length

    // Advance more timers — no new reconnections should happen
    act(() => {
      vi.advanceTimersByTime(60000)
    })

    expect(MockEventSource.instances.length).toBe(instanceCount)
  })

  test('returns error state when max reconnect attempts reached', () => {
    const { result } = renderHook(() => useSSE(), {
      wrapper: createWrapper(),
    })

    // Simulate failed connection cycles to exhaust MAX_RECONNECT_ATTEMPTS.
    // The initial connect creates ES #1. Its error calls scheduleReconnect
    // (attempts: 0 -> 1). The timeout creates ES #2, and so on.
    // After 10 scheduleReconnect calls (attempts=10), the next error
    // triggers scheduleReconnect which sees attempts >= MAX and sets error.
    for (let i = 0; i < 11; i++) {
      act(() => {
        MockEventSource.last().simulateCloseError()
      })
      act(() => {
        vi.advanceTimersByTime(30000)
      })
    }

    expect(result.current.error).toBeInstanceOf(Error)
    expect(result.current.error.message).toBe(
      'SSE connection failed: max reconnect attempts reached'
    )
    expect(result.current.connected).toBe(false)
  })

  test('resets error on successful reconnection', () => {
    const { result } = renderHook(() => useSSE(), {
      wrapper: createWrapper(),
    })

    // Simulate a closed error to start reconnect cycle
    act(() => {
      MockEventSource.last().simulateCloseError()
    })

    // Advance to reconnect
    act(() => {
      vi.advanceTimersByTime(30000)
    })

    // Simulate successful connection on the new EventSource
    const newEs = MockEventSource.last()
    act(() => {
      newEs.simulateEvent('connected')
    })

    expect(result.current.error).toBeNull()
    expect(result.current.connected).toBe(true)
  })

  test('handles pending_change_added events', () => {
    const onPendingChangeAdded = vi.fn()

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    vi.spyOn(queryClient, 'invalidateQueries')

    const wrapper = function Wrapper({ children }) {
      return (
        <QueryClientProvider client={queryClient}>
          {children}
        </QueryClientProvider>
      )
    }

    renderHook(
      () => useSSE({ onPendingChangeAdded }),
      { wrapper }
    )

    const es = MockEventSource.last()

    const eventData = { peer_id: 'peer-123', name: 'test-change' }
    act(() => {
      es.simulateEvent('pending_change_added', eventData)
    })

    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({
      queryKey: ['peers'],
    })
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({
      queryKey: ['pending-changes'],
    })
    expect(onPendingChangeAdded).toHaveBeenCalledWith('peer-123', eventData)
  })

  test('handles parse errors in event data gracefully', () => {
    const onPendingChangeAdded = vi.fn()
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })

    const wrapper = function Wrapper({ children }) {
      return (
        <QueryClientProvider client={queryClient}>
          {children}
        </QueryClientProvider>
      )
    }

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    renderHook(
      () => useSSE({ onPendingChangeAdded }),
      { wrapper }
    )

    const es = MockEventSource.last()

    // Send invalid JSON data
    act(() => {
      es.simulateEvent('pending_change_added', 'not-valid-json')
    })

    // The callback should not have been called
    expect(onPendingChangeAdded).not.toHaveBeenCalled()

    consoleSpy.mockRestore()
  })

  test('sends Last-Event-ID on reconnection after receiving events with IDs', () => {
    renderHook(() => useSSE(), {
      wrapper: createWrapper(),
    })

    const es = MockEventSource.last()

    // Simulate receiving an event with a lastEventId
    act(() => {
      es.simulateEvent('pending_change_added', { peer_id: 'peer-1' }, 'evt-42')
    })

    // Trigger disconnection and reconnect
    act(() => {
      es.simulateCloseError()
    })
    act(() => {
      vi.advanceTimersByTime(30000)
    })

    // The new EventSource should include lastEventId in the URL
    const newEs = MockEventSource.last()
    expect(newEs.url).toContain('lastEventId=evt-42')
  })

  test('does not send Last-Event-ID on initial connection', () => {
    renderHook(() => useSSE(), {
      wrapper: createWrapper(),
    })

    const es = MockEventSource.last()
    expect(es.url).not.toContain('lastEventId')
  })
})
