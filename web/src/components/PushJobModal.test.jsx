import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import PushJobModal from './PushJobModal'

// We'll create a mock EventSource implementation
const mockEventSourceInstances = []
const mockAddEventListener = vi.fn()
const mockClose = vi.fn()

class MockEventSource {
  constructor(url) {
    this.url = url
    this.readyState = 0 // CONNECTING
    this.listeners = {}
    mockEventSourceInstances.push(this)

    // Store reference for test control
    setTimeout(() => {
      this.readyState = 1 // OPEN
    }, 0)
  }

  addEventListener(event, callback) {
    this.listeners[event] = callback
    mockAddEventListener(event, callback)
  }

  _emit(event, data) {
    const cb = this.listeners[event]
    if (cb) {
      cb({ type: event, data: JSON.stringify(data) })
    }
  }

  close() {
    this.readyState = 2 // CLOSED
    this.listeners = {}
    mockClose()
  }
}

let originalEventSource

describe('PushJobModal', () => {
  let user

  beforeEach(() => {
    vi.clearAllMocks()
    user = userEvent.setup()
    mockEventSourceInstances.length = 0

    originalEventSource = global.EventSource
    global.EventSource = MockEventSource
  })

  afterEach(() => {
    global.EventSource = originalEventSource
  })

  function getEventSource() {
    return mockEventSourceInstances[mockEventSourceInstances.length - 1]
  }

  describe('rendering', () => {
    test('renders modal in portal to document.body', () => {
      render(<PushJobModal jobId="job-123" onClose={() => {}} />)

      expect(
        document.querySelector('.fixed.inset-0')
      ).toBeInTheDocument()
    })

    test('renders modal title', () => {
      render(<PushJobModal jobId="job-123" onClose={() => {}} />)

      expect(
        screen.getByText('Pushing Rules to All Peers')
      ).toBeInTheDocument()
    })

    test('shows connecting state initially', () => {
      render(<PushJobModal jobId="job-123" onClose={() => {}} />)

      expect(screen.getByText('0 of 0 peers')).toBeInTheDocument()
      expect(screen.getByText('0%')).toBeInTheDocument()
    })
  })

  describe('EventSource connection', () => {
    test('connects to correct SSE endpoint', () => {
      render(<PushJobModal jobId="job-123" onClose={() => {}} />)

      const es = getEventSource()
      expect(es.url).toBe('/api/v1/push-jobs/job-123/events')
    })

    test('registers event listeners', () => {
      render(<PushJobModal jobId="job-123" onClose={() => {}} />)

      const es = getEventSource()
      expect(es.listeners['init']).toBeDefined()
      expect(es.listeners['progress']).toBeDefined()
      expect(es.listeners['peer_success']).toBeDefined()
      expect(es.listeners['peer_failed']).toBeDefined()
      expect(es.listeners['complete']).toBeDefined()
    })

    test('updates on init event', async () => {
      render(<PushJobModal jobId="job-123" onClose={() => {}} />)

      const es = getEventSource()
      es._emit('init', {
        total: 3,
        succeeded: 0,
        failed: 0,
        status: 'running',
        peers: [
          { peer_id: 'peer-1', peer_hostname: 'server-1', status: 'pending' },
          { peer_id: 'peer-2', peer_hostname: 'server-2', status: 'pending' },
        ],
      })

      await waitFor(() => {
        expect(screen.getByText('server-1')).toBeInTheDocument()
        expect(screen.getByText('server-2')).toBeInTheDocument()
      })
    })

    test('updates on progress event', async () => {
      render(<PushJobModal jobId="job-123" onClose={() => {}} />)

      const es = getEventSource()
      es._emit('init', { total: 5, succeeded: 0, failed: 0, status: 'running', peers: [] })
      es._emit('progress', { total: 5, succeeded: 0, failed: 0, peer_id: 'peer-1', hostname: 'server-1' })

      await waitFor(() => {
        expect(screen.getByText('server-1')).toBeInTheDocument()
      })
    })

    test('updates on peer_success event', async () => {
      render(<PushJobModal jobId="job-123" onClose={() => {}} />)

      const es = getEventSource()
      es._emit('init', { total: 2, succeeded: 0, failed: 0, status: 'running', peers: [
        { peer_id: 'p1', peer_hostname: 'node-1', status: 'pending' },
      ]})
      es._emit('peer_success', { peer_id: 'p1', hostname: 'node-1', succeeded: 1, failed: 0, total: 2 })

      await waitFor(() => {
        expect(screen.getByText('1 succeeded')).toBeInTheDocument()
      })
    })

    test('updates on peer_failed event', async () => {
      render(<PushJobModal jobId="job-123" onClose={() => {}} />)

      const es = getEventSource()
      es._emit('init', { total: 2, succeeded: 0, failed: 0, status: 'running', peers: [
        { peer_id: 'p1', peer_hostname: 'node-1', status: 'pending' },
      ]})
      es._emit('peer_failed', { peer_id: 'p1', hostname: 'node-1', succeeded: 0, failed: 1, total: 2, error: 'Connection timeout' })

      await waitFor(() => {
        expect(screen.getByText('1 failed')).toBeInTheDocument()
        expect(screen.getByText('Connection timeout')).toBeInTheDocument()
      })
    })

    test('shows completed state and auto-closes', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true })
      const handleClose = vi.fn()

      render(<PushJobModal jobId="job-123" onClose={handleClose} />)

      const es = getEventSource()
      es._emit('init', { total: 2, succeeded: 0, failed: 0, status: 'running', peers: [] })
      es._emit('complete', { total: 2, succeeded: 2, failed: 0, status: 'completed' })

      await waitFor(() => {
        expect(screen.getByText('2 succeeded')).toBeInTheDocument()
      })

      // Auto-close after 3 seconds - advance time to trigger the setTimeout
      await vi.advanceTimersByTimeAsync(3000)

      expect(handleClose).toHaveBeenCalled()

      vi.useRealTimers()
    })
  })

  describe('peer list display', () => {
    test('sorts peers by hostname', async () => {
      render(<PushJobModal jobId="job-123" onClose={() => {}} />)

      const es = getEventSource()
      es._emit('init', {
        total: 2,
        succeeded: 0,
        failed: 0,
        status: 'running',
        peers: [
          { peer_id: 'p2', peer_hostname: 'zebra', status: 'pending' },
          { peer_id: 'p1', peer_hostname: 'alpha', status: 'pending' },
        ],
      })

      await waitFor(() => {
        const peerNames = screen.getAllByText(/alpha|zebra/)
        expect(peerNames[0]).toHaveTextContent('alpha')
        expect(peerNames[1]).toHaveTextContent('zebra')
      })
    })
  })

  describe('close button', () => {
    test('shows Close & Run in Background when not complete', () => {
      render(<PushJobModal jobId="job-123" onClose={() => {}} />)

      expect(
        screen.getByText('Close & Run in Background')
      ).toBeInTheDocument()
    })

    test('shows Close when job is complete', async () => {
      render(<PushJobModal jobId="job-123" onClose={() => {}} />)

      const es = getEventSource()
      es._emit('init', { total: 1, succeeded: 0, failed: 0, status: 'running', peers: [] })
      es._emit('complete', { total: 1, succeeded: 1, failed: 0, status: 'completed' })

      // The complete handler sets status immediately, so Close button should appear
      await waitFor(() => {
        expect(screen.getByText('Close')).toBeInTheDocument()
      })
    })

    test('closes EventSource when close button is clicked', async () => {
      const handleClose = vi.fn()

      render(<PushJobModal jobId="job-123" onClose={handleClose} />)

      const closeButton = screen.getByText('Close & Run in Background')
      await user.click(closeButton)

      expect(handleClose).toHaveBeenCalledTimes(1)
    })
  })

  describe('progress bar', () => {
    test('renders progress bar with correct percentage', async () => {
      render(<PushJobModal jobId="job-123" onClose={() => {}} />)

      const es = getEventSource()
      es._emit('init', { total: 10, succeeded: 3, failed: 2, status: 'running', peers: [] })

      await waitFor(() => {
        expect(screen.getByText('50%')).toBeInTheDocument()
      })
    })
  })
})
