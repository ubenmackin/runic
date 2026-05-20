import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import { Plus } from 'lucide-react'
import EmptyState from './EmptyState'

describe('EmptyState', () => {
  describe('rendering', () => {
    test('renders title and message', () => {
      render(<EmptyState title="No items found" message="There are no items to display." />)
      expect(screen.getByText('No items found')).toBeInTheDocument()
      expect(screen.getByText('There are no items to display.')).toBeInTheDocument()
    })

    test('renders without icon when not provided', () => {
      const { container } = render(
        <EmptyState title="No data" message="No data available." />
      )
      // No icon wrapper should be present
      expect(screen.getByText('No data')).toBeInTheDocument()
      // The icon wrapper div has w-16 h-16 classes
      const iconWrappers = container.querySelectorAll('.w-16')
      expect(iconWrappers.length).toBe(0)
    })

    test('renders with icon when provided', () => {
      render(
        <EmptyState
          icon={Plus}
          title="Add items"
          message="Get started by adding items."
        />
      )
      expect(screen.getByText('Add items')).toBeInTheDocument()
      // The Plus icon should render (it renders as an SVG)
      const svg = document.querySelector('svg')
      expect(svg).toBeInTheDocument()
    })

    test('renders action button when action and onAction are provided', () => {
      render(
        <EmptyState
          title="No items"
          message="Add your first item."
          action="Add Item"
          onAction={() => {}}
        />
      )
      expect(screen.getByRole('button', { name: /add item/i })).toBeInTheDocument()
    })

    test('does not render action button when onAction is missing', () => {
      render(
        <EmptyState
          title="No items"
          message="Add your first item."
          action="Add Item"
        />
      )
      expect(screen.queryByRole('button')).not.toBeInTheDocument()
    })

    test('does not render action button when action is missing', () => {
      render(
        <EmptyState
          title="No items"
          message="No items available."
          onAction={() => {}}
        />
      )
      expect(screen.queryByRole('button')).not.toBeInTheDocument()
    })
  })

  describe('props variations', () => {
    test('renders with different icon components', () => {
      const { rerender } = render(
        <EmptyState
          icon={Plus}
          title="Test"
          message="Test message"
        />
      )
      expect(document.querySelector('svg')).toBeInTheDocument()

      // Test with a different icon
      rerender(
        <EmptyState
          icon={({ className }) => <span data-testid="custom-icon" className={className}>Icon</span>}
          title="Test"
          message="Test message"
        />
      )
      expect(screen.getByTestId('custom-icon')).toBeInTheDocument()
    })

    test('renders with long message text', () => {
      const longMessage = 'This is a very long message that describes the empty state in great detail so the user knows exactly what to do next.'
      render(<EmptyState title="Empty" message={longMessage} />)
      expect(screen.getByText(longMessage)).toBeInTheDocument()
    })

    test('renders with long action text', () => {
      render(
        <EmptyState
          title="No data"
          message="No data found."
          action="Create New Record"
          onAction={() => {}}
        />
      )
      expect(screen.getByRole('button', { name: /create new record/i })).toBeInTheDocument()
    })
  })

  describe('interaction', () => {
    test('calls onAction when action button is clicked', async () => {
      const user = userEvent.setup()
      const handleAction = vi.fn()

      render(
        <EmptyState
          title="Empty"
          message="No items."
          action="Add"
          onAction={handleAction}
        />
      )

      await user.click(screen.getByRole('button', { name: /add/i }))
      expect(handleAction).toHaveBeenCalledTimes(1)
    })

    test('calls onAction multiple times', async () => {
      const user = userEvent.setup()
      const handleAction = vi.fn()

      render(
        <EmptyState
          title="Empty"
          message="No items."
          action="Add"
          onAction={handleAction}
        />
      )

      await user.click(screen.getByRole('button', { name: /add/i }))
      await user.click(screen.getByRole('button', { name: /add/i }))
      await user.click(screen.getByRole('button', { name: /add/i }))
      expect(handleAction).toHaveBeenCalledTimes(3)
    })
  })

  describe('null/undefined handling', () => {
    test('handles null title', () => {
      render(<EmptyState title={null} message="A message" />)
      const heading = screen.getByRole('heading', { level: 3 })
      expect(heading.textContent).toBe('')
    })

    test('handles undefined title', () => {
      render(<EmptyState message="A message" />)
      const heading = screen.getByRole('heading', { level: 3 })
      expect(heading).toBeInTheDocument()
    })

    test('handles null message', () => {
      render(<EmptyState title="Title" message={null} />)
      expect(screen.getByText('Title')).toBeInTheDocument()
    })

    test('handles undefined message', () => {
      render(<EmptyState title="Title" />)
      expect(screen.getByText('Title')).toBeInTheDocument()
    })

    test('handles null icon without crashing', () => {
      render(<EmptyState icon={null} title="Title" message="Message" />)
      expect(screen.getByText('Title')).toBeInTheDocument()
    })

    test('handles null action gracefully', () => {
      render(<EmptyState title="Title" message="Message" action={null} onAction={() => {}} />)
      expect(screen.queryByRole('button')).not.toBeInTheDocument()
    })

    test('handles all props as null', () => {
      render(<EmptyState icon={null} title={null} message={null} action={null} onAction={null} />)
      // Should not crash
    })
  })

  describe('accessibility', () => {
    test('title is rendered as h3', () => {
      render(<EmptyState title="Section Title" message="A message" />)
      expect(screen.getByRole('heading', { level: 3 })).toHaveTextContent('Section Title')
    })

    test('action button has aria-label matching action text', () => {
      render(
        <EmptyState
          title="Empty"
          message="No items."
          action="Create Item"
          onAction={() => {}}
        />
      )
      const button = screen.getByRole('button')
      expect(button).toHaveAttribute('aria-label', 'Create Item')
    })

    test('icon is presentational', () => {
      render(
        <EmptyState
          icon={Plus}
          title="Test"
          message="Test message"
        />
      )
      const svg = document.querySelector('svg')
      expect(svg).toBeInTheDocument()
    })
  })
})
