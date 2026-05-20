import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import FilterChip from './FilterChip'

describe('FilterChip', () => {
  describe('rendering', () => {
    test('renders with label', () => {
      render(<FilterChip label="Active" />)
      expect(screen.getByText('Active')).toBeInTheDocument()
    })

    test('renders as a button', () => {
      render(<FilterChip label="Filter" />)
      expect(screen.getByRole('button')).toBeInTheDocument()
    })
  })

  describe('props variations', () => {
    test('renders in unselected state by default - aria-pressed not present', () => {
      render(<FilterChip label="All" />)
      const button = screen.getByRole('button')
      // When selected is not provided (undefined), React omits aria-pressed
      expect(button).not.toHaveAttribute('aria-pressed')
    })

    test('renders in selected state', () => {
      render(<FilterChip label="All" selected={true} />)
      const button = screen.getByRole('button')
      expect(button).toHaveAttribute('aria-pressed', 'true')
    })

    test('renders in unselected state when selected is false', () => {
      render(<FilterChip label="All" selected={false} />)
      const button = screen.getByRole('button')
      expect(button).toHaveAttribute('aria-pressed', 'false')
    })

    test('renders with long label text', () => {
      const longLabel = 'A very long filter option name that should still render'
      render(<FilterChip label={longLabel} />)
      expect(screen.getByText(longLabel)).toBeInTheDocument()
    })
  })

  describe('selected styling', () => {
    test('selected state has purple background', () => {
      render(<FilterChip label="Active" selected={true} />)
      const button = screen.getByRole('button')
      expect(button.className).toContain('bg-purple-active')
      expect(button.className).toContain('text-white')
    })

    test('unselected state has white background', () => {
      render(<FilterChip label="Active" selected={false} />)
      const button = screen.getByRole('button')
      expect(button.className).toContain('bg-white')
      expect(button.className).toContain('text-gray-700')
    })

    test('selected state has purple border', () => {
      render(<FilterChip label="Active" selected={true} />)
      const button = screen.getByRole('button')
      expect(button.className).toContain('border-purple-active')
    })

    test('unselected state has gray border', () => {
      render(<FilterChip label="Active" selected={false} />)
      const button = screen.getByRole('button')
      expect(button.className).toContain('border-gray-300')
    })
  })

  describe('interaction', () => {
    test('calls onClick when clicked', async () => {
      const user = userEvent.setup()
      const handleClick = vi.fn()

      render(<FilterChip label="Click me" onClick={handleClick} />)

      await user.click(screen.getByRole('button'))
      expect(handleClick).toHaveBeenCalledTimes(1)
    })

    test('calls onClick multiple times', async () => {
      const user = userEvent.setup()
      const handleClick = vi.fn()

      render(<FilterChip label="Click me" onClick={handleClick} />)

      await user.click(screen.getByRole('button'))
      await user.click(screen.getByRole('button'))
      await user.click(screen.getByRole('button'))
      expect(handleClick).toHaveBeenCalledTimes(3)
    })

    test('handles click with selected state', async () => {
      const user = userEvent.setup()
      const handleClick = vi.fn()

      render(<FilterChip label="Toggle" selected={true} onClick={handleClick} />)

      await user.click(screen.getByRole('button'))
      expect(handleClick).toHaveBeenCalledTimes(1)
    })
  })

  describe('null/undefined handling', () => {
    test('handles undefined label', () => {
      render(<FilterChip label={undefined} />)
      const button = screen.getByRole('button')
      expect(button.textContent).toBe('')
    })

    test('handles null label', () => {
      render(<FilterChip label={null} />)
      const button = screen.getByRole('button')
      expect(button.textContent).toBe('')
    })

    test('handles undefined selected - attribute omitted', () => {
      render(<FilterChip label="Test" />)
      const button = screen.getByRole('button')
      // When selected is undefined, React omits the aria-pressed attribute
      expect(button).not.toHaveAttribute('aria-pressed')
    })

    test('handles null selected - attribute omitted', () => {
      render(<FilterChip label="Test" selected={null} />)
      const button = screen.getByRole('button')
      // When selected is null, React omits the aria-pressed attribute
      expect(button).not.toHaveAttribute('aria-pressed')
    })

    test('handles undefined onClick without crashing', () => {
      render(<FilterChip label="Test" />)
      const button = screen.getByRole('button')
      expect(() => button.click()).not.toThrow()
    })

    test('handles null onClick', () => {
      render(<FilterChip label="Test" onClick={null} />)
      const button = screen.getByRole('button')
      expect(() => button.click()).not.toThrow()
    })
  })

  describe('accessibility', () => {
    test('has button role', () => {
      render(<FilterChip label="Filter" />)
      expect(screen.getByRole('button')).toBeInTheDocument()
    })

    test('has aria-pressed attribute when selected', () => {
      render(<FilterChip label="Active" selected={true} />)
      const button = screen.getByRole('button')
      expect(button).toHaveAttribute('aria-pressed', 'true')
    })

    test('has aria-pressed attribute when not selected', () => {
      render(<FilterChip label="Active" selected={false} />)
      const button = screen.getByRole('button')
      expect(button).toHaveAttribute('aria-pressed', 'false')
    })

    test('has aria-label matching label', () => {
      render(<FilterChip label="Filter by status" />)
      const button = screen.getByRole('button')
      expect(button).toHaveAttribute('aria-label', 'Filter by status')
    })

    test('aria-label updates with label', () => {
      const { rerender } = render(<FilterChip label="Online" />)
      expect(screen.getByRole('button')).toHaveAttribute('aria-label', 'Online')

      rerender(<FilterChip label="Offline" />)
      expect(screen.getByRole('button')).toHaveAttribute('aria-label', 'Offline')
    })
  })
})
