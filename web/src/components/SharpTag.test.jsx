import { render, screen } from '@testing-library/react'
import { describe, test, expect } from 'vitest'
import SharpTag from './SharpTag'

describe('SharpTag', () => {
  describe('rendering', () => {
    test('renders status text in uppercase', () => {
      render(<SharpTag status="online" />)

      expect(screen.getByText('[ONLINE]')).toBeInTheDocument()
    })

    test('renders status with brackets', () => {
      render(<SharpTag status="synced" />)

      expect(screen.getByText('[SYNCED]')).toBeInTheDocument()
    })

    test('renders status case-insensitively', () => {
      render(<SharpTag status="OFFLINE" />)

      expect(screen.getByText('[OFFLINE]')).toBeInTheDocument()
    })

    test('defaults to PENDING when no status provided', () => {
      render(<SharpTag />)

      expect(screen.getByText('[PENDING]')).toBeInTheDocument()
    })

    test('handles null status', () => {
      render(<SharpTag status={null} />)

      expect(screen.getByText('[PENDING]')).toBeInTheDocument()
    })

    test('handles undefined status', () => {
      render(<SharpTag status={undefined} />)

      expect(screen.getByText('[PENDING]')).toBeInTheDocument()
    })
  })

  describe('color variants', () => {
    test('applies synced color classes', () => {
      const { container } = render(<SharpTag status="synced" />)

      const tag = container.firstChild
      expect(tag.className).toContain('border-green-500')
      expect(tag.className).toContain('text-green-600')
    })

    test('applies online color classes', () => {
      const { container } = render(<SharpTag status="online" />)

      const tag = container.firstChild
      expect(tag.className).toContain('border-green-500')
      expect(tag.className).toContain('text-green-500')
    })

    test('applies offline color classes', () => {
      const { container } = render(<SharpTag status="offline" />)

      const tag = container.firstChild
      expect(tag.className).toContain('border-red-500')
      expect(tag.className).toContain('text-red-500')
    })

    test('applies pending color classes', () => {
      const { container } = render(<SharpTag status="pending" />)

      const tag = container.firstChild
      expect(tag.className).toContain('border-amber-500')
      expect(tag.className).toContain('text-amber-500')
    })

    test('applies critical color classes', () => {
      const { container } = render(<SharpTag status="critical" />)

      const tag = container.firstChild
      expect(tag.className).toContain('border-red-500')
      expect(tag.className).toContain('text-red-500')
    })

    test('applies warning color classes', () => {
      const { container } = render(<SharpTag status="warning" />)

      const tag = container.firstChild
      expect(tag.className).toContain('border-amber-500')
      expect(tag.className).toContain('text-amber-500')
    })

    test('applies info color classes', () => {
      const { container } = render(<SharpTag status="info" />)

      const tag = container.firstChild
      expect(tag.className).toContain('border-blue-500')
      expect(tag.className).toContain('text-blue-500')
    })

    test('defaults to pending color for unknown status', () => {
      const { container } = render(<SharpTag status="unknown-status" />)

      const tag = container.firstChild
      expect(tag.className).toContain('border-amber-500')
      expect(tag.className).toContain('text-amber-500')
    })
  })

  describe('custom color', () => {
    test('accepts custom color classes', () => {
      const { container } = render(
        <SharpTag status="custom" color="border-pink-500 text-pink-500" />
      )

      const tag = container.firstChild
      expect(tag.className).toContain('border-pink-500')
      expect(tag.className).toContain('text-pink-500')
    })

    test('custom color overrides default status color', () => {
      const { container } = render(
        <SharpTag status="online" color="border-cyan-500 text-cyan-500" />
      )

      const tag = container.firstChild
      expect(tag.className).toContain('border-cyan-500')
      expect(tag.className).toContain('text-cyan-500')
      expect(tag.className).not.toContain('border-green-500')
    })
  })

  describe('styling', () => {
    test('has inline-block display', () => {
      const { container } = render(<SharpTag status="online" />)

      const tag = container.firstChild
      expect(tag.className).toContain('inline-block')
    })

    test('has correct padding', () => {
      const { container } = render(<SharpTag status="online" />)

      const tag = container.firstChild
      expect(tag.className).toContain('px-1.5')
      expect(tag.className).toContain('py-0.5')
    })

    test('has border', () => {
      const { container } = render(<SharpTag status="online" />)

      const tag = container.firstChild
      expect(tag.className).toContain('border')
    })

    test('has mono font', () => {
      const { container } = render(<SharpTag status="online" />)

      const tag = container.firstChild
      expect(tag.className).toContain('font-mono')
    })

    test('has small text size', () => {
      const { container } = render(<SharpTag status="online" />)

      const tag = container.firstChild
      expect(tag.className).toContain('text-[10px]')
    })
  })

  describe('accessibility', () => {
    test('is a span element', () => {
      const { container } = render(<SharpTag status="online" />)

      expect(container.firstChild.tagName).toBe('SPAN')
    })
  })
})
