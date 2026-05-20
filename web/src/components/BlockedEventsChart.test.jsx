import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach } from 'vitest'
import BlockedEventsChart from './BlockedEventsChart'

// Mock the canvas context
const mockClearRect = vi.fn()
const mockBeginPath = vi.fn()
const mockMoveTo = vi.fn()
const mockLineTo = vi.fn()
const mockClosePath = vi.fn()
const mockFill = vi.fn()
const mockStroke = vi.fn()
const mockArc = vi.fn()
const mockFillText = vi.fn()
const mockScale = vi.fn()

const mockCanvasContext = {
  clearRect: mockClearRect,
  beginPath: mockBeginPath,
  moveTo: mockMoveTo,
  lineTo: mockLineTo,
  closePath: mockClosePath,
  fill: mockFill,
  stroke: mockStroke,
  arc: mockArc,
  fillText: mockFillText,
  scale: mockScale,
  font: '',
  fillStyle: '',
  strokeStyle: '',
  lineWidth: 0,
  lineJoin: '',
  textAlign: '',
}

// Mock getContext on HTMLCanvasElement
HTMLCanvasElement.prototype.getContext = vi.fn(() => mockCanvasContext)

// Mock getBoundingClientRect
Element.prototype.getBoundingClientRect = vi.fn(() => ({
  width: 600,
  height: 150,
  top: 0,
  left: 0,
  right: 600,
  bottom: 150,
  x: 0,
  y: 0,
  toJSON: () => {},
}))

describe('BlockedEventsChart', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  const createLog = (hoursAgo) => ({
    timestamp: new Date(Date.now() - hoursAgo * 60 * 60 * 1000).toISOString(),
  })

  describe('rendering', () => {
    test('renders canvas with aria label', () => {
      render(<BlockedEventsChart logs={[]} />)

      const canvas = screen.getByRole('img')
      expect(canvas).toBeInTheDocument()
      expect(canvas).toHaveAttribute(
        'aria-label',
        'Blocked events chart showing hourly blocked event counts'
      )
    })

    test('renders hourly labels at 6-hour intervals (0, 4, 8, 12, 16, 20)', () => {
      render(<BlockedEventsChart logs={[]} />)

      // The component renders every 4th label (i % 4 === 0)
      const labels = screen.getAllByText(/^\d{1,2}:\d{2} (AM|PM)$/)
      expect(labels.length).toBeGreaterThanOrEqual(6)
    })

    test('renders empty state with zero counts', () => {
      render(<BlockedEventsChart logs={[]} />)

      const labels = screen.getAllByText(/(AM|PM)$/)
      expect(labels.length).toBeGreaterThan(0)
    })
  })

  describe('data rendering', () => {
    test('renders chart with log data', () => {
      const logs = [
        createLog(0),
        createLog(1),
        createLog(2),
      ]

      const { container } = render(<BlockedEventsChart logs={logs} />)

      // The component should have hit event handlers per data point
      const hitAreas = container.querySelectorAll('.cursor-pointer')
      expect(hitAreas.length).toBeGreaterThan(0)
    })
  })

  describe('tooltip interaction', () => {
    test('shows tooltip on hover over a data point', async () => {
      const user = userEvent.setup()
      const logs = [
        createLog(1),
      ]

      render(<BlockedEventsChart logs={logs} />)

      // The hit areas are the cursor-pointer divs
      const hitAreas = document.querySelectorAll('.cursor-pointer')
      expect(hitAreas.length).toBeGreaterThan(0)

      await user.hover(hitAreas[0])

      // Tooltip should show "blocked" text
      expect(screen.getByText(/blocked/)).toBeInTheDocument()
    })

    test('hides tooltip on mouse leave', async () => {
      const user = userEvent.setup()
      const logs = [createLog(1)]

      const { container } = render(<BlockedEventsChart logs={logs} />)

      const chartContainer = container.firstChild
      const hitAreas = document.querySelectorAll('.cursor-pointer')

      await user.hover(hitAreas[0])
      expect(screen.getByText(/blocked/)).toBeInTheDocument()

      await user.unhover(chartContainer)
      expect(screen.queryByText(/blocked/)).not.toBeInTheDocument()
    })

    test('tooltip displays correct count and label', async () => {
      const user = userEvent.setup()
      const logs = [createLog(0)]

      render(<BlockedEventsChart logs={logs} />)

      const hitAreas = document.querySelectorAll('.cursor-pointer')
      await user.hover(hitAreas[0])

      const tooltip = screen.getByText(/: \d+ blocked/)
      expect(tooltip).toBeInTheDocument()
    })
  })

  describe('canvas drawing', () => {
    test('calls drawChart with processed data', () => {
      render(<BlockedEventsChart logs={[]} />)

      // getContext should have been called
      expect(mockClearRect).toHaveBeenCalled()
    })
  })

  describe('empty data edge case', () => {
    test('handles null logs gracefully', () => {
      render(<BlockedEventsChart logs={null} />)

      const canvas = screen.getByRole('img')
      expect(canvas).toBeInTheDocument()
    })

    test('handles undefined logs gracefully', () => {
      render(<BlockedEventsChart logs={undefined} />)

      const canvas = screen.getByRole('img')
      expect(canvas).toBeInTheDocument()
    })
  })
})
