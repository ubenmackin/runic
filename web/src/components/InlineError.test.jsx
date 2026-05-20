import { render, screen } from '@testing-library/react'
import { describe, test, expect } from 'vitest'
import InlineError from './InlineError'

describe('InlineError', () => {
  describe('rendering', () => {
    test('renders error message', () => {
      render(<InlineError message="This field is required" />)
      expect(screen.getByText('This field is required')).toBeInTheDocument()
    })

    test('renders different error messages', () => {
      const { rerender } = render(<InlineError message="Invalid input" />)
      expect(screen.getByText('Invalid input')).toBeInTheDocument()

      rerender(<InlineError message="Network error" />)
      expect(screen.getByText('Network error')).toBeInTheDocument()
    })

    test('renders with special characters', () => {
      render(<InlineError message="Error: Something went wrong (code: 500)!" />)
      expect(screen.getByText('Error: Something went wrong (code: 500)!')).toBeInTheDocument()
    })

    test('renders with long error message', () => {
      const longMessage = 'A very long error message that provides detailed information about what went wrong and how the user might resolve the issue.'
      render(<InlineError message={longMessage} />)
      expect(screen.getByText(longMessage)).toBeInTheDocument()
    })
  })

  describe('null/undefined handling', () => {
    test('returns null when message is null', () => {
      const { container } = render(<InlineError message={null} />)
      expect(container.innerHTML).toBe('')
    })

    test('returns null when message is undefined', () => {
      const { container } = render(<InlineError message={undefined} />)
      expect(container.innerHTML).toBe('')
    })

    test('returns null when message is empty string', () => {
      const { container } = render(<InlineError message="" />)
      expect(container.innerHTML).toBe('')
    })

    test('returns null when no message prop provided', () => {
      const { container } = render(<InlineError />)
      expect(container.innerHTML).toBe('')
    })
  })

  describe('styling', () => {
    test('has red text color', () => {
      const { container } = render(<InlineError message="Error text" />)
      const element = container.firstChild
      expect(element.className).toContain('text-red-600')
    })

    test('has small text size', () => {
      const { container } = render(<InlineError message="Error" />)
      const element = container.firstChild
      expect(element.className).toContain('text-sm')
    })

    test('has top margin', () => {
      const { container } = render(<InlineError message="Error" />)
      const element = container.firstChild
      expect(element.className).toContain('mt-1')
    })
  })

  describe('accessibility', () => {
    test('is rendered as a paragraph element', () => {
      render(<InlineError message="Error message" />)
      const element = screen.getByText('Error message')
      expect(element.tagName).toBe('P')
    })
  })
})
