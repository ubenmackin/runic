import { render, screen } from '@testing-library/react'
import { describe, test, expect } from 'vitest'
import StatusBadge from './StatusBadge'

describe('StatusBadge', () => {
  describe('rendering', () => {
    test('renders online status', () => {
      render(<StatusBadge status="online" />)
      expect(screen.getByText('[Online]')).toBeInTheDocument()
    })

    test('renders offline status', () => {
      render(<StatusBadge status="offline" />)
      expect(screen.getByText('[Offline]')).toBeInTheDocument()
    })

    test('renders pending status', () => {
      render(<StatusBadge status="pending" />)
      expect(screen.getByText('[Pending]')).toBeInTheDocument()
    })

    test('renders error status', () => {
      render(<StatusBadge status="error" />)
      expect(screen.getByText('[Error]')).toBeInTheDocument()
    })
  })

  describe('props variations', () => {
    test('defaults to pending for unknown status', () => {
      render(<StatusBadge status="unknown" />)
      expect(screen.getByText('[Pending]')).toBeInTheDocument()
    })

    test('defaults to pending for invalid status', () => {
      render(<StatusBadge status="invalid-status" />)
      expect(screen.getByText('[Pending]')).toBeInTheDocument()
    })

    test('defaults to pending for empty string status', () => {
      render(<StatusBadge status="" />)
      expect(screen.getByText('[Pending]')).toBeInTheDocument()
    })
  })

  describe('null/undefined handling', () => {
    test('handles undefined status', () => {
      render(<StatusBadge />)
      expect(screen.getByText('[Pending]')).toBeInTheDocument()
    })

    test('handles null status', () => {
      render(<StatusBadge status={null} />)
      expect(screen.getByText('[Pending]')).toBeInTheDocument()
    })
  })

  describe('color classes per status', () => {
    test('online has green border and text', () => {
      const { container } = render(<StatusBadge status="online" />)
      const badge = container.firstChild
      expect(badge.className).toContain('border-green-500')
      expect(badge.className).toContain('text-green-700')
    })

    test('offline has red border and text', () => {
      const { container } = render(<StatusBadge status="offline" />)
      const badge = container.firstChild
      expect(badge.className).toContain('border-red-500')
      expect(badge.className).toContain('text-red-700')
    })

    test('pending has amber border and text', () => {
      const { container } = render(<StatusBadge status="pending" />)
      const badge = container.firstChild
      expect(badge.className).toContain('border-amber-500')
      expect(badge.className).toContain('text-amber-700')
    })

    test('error has red border and text', () => {
      const { container } = render(<StatusBadge status="error" />)
      const badge = container.firstChild
      expect(badge.className).toContain('border-red-500')
      expect(badge.className).toContain('text-red-700')
    })

    test('unknown status defaults to pending colors', () => {
      const { container } = render(<StatusBadge status="whatevs" />)
      const badge = container.firstChild
      expect(badge.className).toContain('border-amber-500')
      expect(badge.className).toContain('text-amber-700')
    })
  })

  describe('accessibility', () => {
    test('is a span element', () => {
      const { container } = render(<StatusBadge status="online" />)
      expect(container.firstChild.tagName).toBe('SPAN')
    })
  })

  describe('styling', () => {
    test('has inline-block display', () => {
      const { container } = render(<StatusBadge status="online" />)
      const badge = container.firstChild
      expect(badge.className).toContain('inline-block')
    })

    test('has correct padding', () => {
      const { container } = render(<StatusBadge status="online" />)
      const badge = container.firstChild
      expect(badge.className).toContain('px-1.5')
      expect(badge.className).toContain('py-0.5')
    })

    test('has border', () => {
      const { container } = render(<StatusBadge status="online" />)
      const badge = container.firstChild
      expect(badge.className).toContain('border')
    })

    test('has mono font', () => {
      const { container } = render(<StatusBadge status="online" />)
      const badge = container.firstChild
      expect(badge.className).toContain('font-mono')
    })

    test('has small text size', () => {
      const { container } = render(<StatusBadge status="online" />)
      const badge = container.firstChild
      expect(badge.className).toContain('text-[10px]')
    })
  })
})
