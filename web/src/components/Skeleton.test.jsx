import { render, screen } from '@testing-library/react'
import { describe, test, expect } from 'vitest'
import Skeleton from './Skeleton'

describe('Skeleton', () => {
  describe('rendering', () => {
    test('renders without crashing', () => {
      render(<Skeleton />)
      const element = screen.getByRole('status')
      expect(element).toBeInTheDocument()
    })

    test('renders with default dimensions', () => {
      render(<Skeleton />)
      const element = screen.getByRole('status')
      expect(element.style.width).toBe('100%')
      expect(element.style.height).toBe('1rem')
    })

    test('renders with custom width and height', () => {
      render(<Skeleton width="200px" height="2rem" />)
      const element = screen.getByRole('status')
      expect(element.style.width).toBe('200px')
      expect(element.style.height).toBe('2rem')
    })

    test('accepts additional className', () => {
      const { container } = render(<Skeleton className="extra-class" />)
      const element = container.firstChild
      expect(element.className).toContain('extra-class')
    })
  })

  describe('props variations', () => {
    test('renders with percentage width', () => {
      render(<Skeleton width="50%" />)
      const element = screen.getByRole('status')
      expect(element.style.width).toBe('50%')
    })

    test('renders with pixel height', () => {
      render(<Skeleton height="24px" />)
      const element = screen.getByRole('status')
      expect(element.style.height).toBe('24px')
    })

    test('renders with zero width as string "0"', () => {
      render(<Skeleton width="0" />)
      const element = screen.getByRole('status')
      // React normalizes "0" to "0px" in style
      expect(element.style.width).toBe('0px')
    })
  })

  describe('null/undefined handling', () => {
    test('handles undefined width - uses default', () => {
      render(<Skeleton width={undefined} />)
      const element = screen.getByRole('status')
      expect(element.style.width).toBe('100%')
    })

    test('handles undefined height - uses default', () => {
      render(<Skeleton height={undefined} />)
      const element = screen.getByRole('status')
      expect(element.style.height).toBe('1rem')
    })

    test('handles undefined className', () => {
      render(<Skeleton className={undefined} />)
      const element = screen.getByRole('status')
      expect(element).toBeInTheDocument()
    })
  })

  describe('accessibility', () => {
    test('has role="status"', () => {
      render(<Skeleton />)
      expect(screen.getByRole('status')).toBeInTheDocument()
    })

    test('has aria-label "Loading"', () => {
      render(<Skeleton />)
      const element = screen.getByRole('status')
      expect(element).toHaveAttribute('aria-label', 'Loading')
    })
  })

  describe('styling', () => {
    test('has animate-pulse class', () => {
      const { container } = render(<Skeleton />)
      const element = container.firstChild
      expect(element.className).toContain('animate-pulse')
    })

    test('has base background class', () => {
      const { container } = render(<Skeleton />)
      const element = container.firstChild
      expect(element.className).toContain('bg-gray-200')
    })

    test('custom className is appended', () => {
      const { container } = render(<Skeleton className="my-custom-class" />)
      const element = container.firstChild
      expect(element.className).toContain('my-custom-class')
      expect(element.className).toContain('animate-pulse') // base class preserved
    })
  })
})
