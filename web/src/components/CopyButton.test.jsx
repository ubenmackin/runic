import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import CopyButton from './CopyButton'

describe('CopyButton', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('rendering', () => {
    test('renders a button', () => {
      render(<CopyButton text="copy me" />)

      expect(screen.getByRole('button')).toBeInTheDocument()
    })

    test('renders with default label in aria-label', () => {
      render(<CopyButton text="copy me" />)

      const button = screen.getByRole('button')
      expect(button).toHaveAttribute('aria-label', 'Copy')
    })

    test('renders with custom label in aria-label', () => {
      render(<CopyButton text="copy me" label="Copy Diff" />)

      const button = screen.getByRole('button')
      expect(button).toHaveAttribute('aria-label', 'Copy Diff')
    })

    test('renders Copy icon by default', () => {
      const { container } = render(<CopyButton text="copy me" />)

      // Copy icon is rendered as SVG
      const svg = container.querySelector('svg')
      expect(svg).toBeInTheDocument()
    })
  })

  describe('interaction', () => {
    test('calls navigator.clipboard.writeText when clicked', async () => {
      const user = userEvent.setup()
      const writeTextMock = vi.fn().mockResolvedValue(undefined)
      vi.spyOn(navigator.clipboard, 'writeText').mockImplementation(writeTextMock)

      render(<CopyButton text="test content" />)

      await user.click(screen.getByRole('button'))

      expect(writeTextMock).toHaveBeenCalledWith('test content')
    })

    test('shows check icon after successful copy', async () => {
      const user = userEvent.setup()
      vi.useFakeTimers()
      vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue(undefined)

      render(<CopyButton text="test content" />)

      await user.click(screen.getByRole('button'))

      // After clicking, aria-label should change to 'Copied'
      const button = screen.getByRole('button')
      expect(button).toHaveAttribute('aria-label', 'Copied')

      vi.useRealTimers()
    })

    test('reverts to copy icon after timeout', async () => {
      const user = userEvent.setup()
      vi.useFakeTimers()
      vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue(undefined)

      render(<CopyButton text="test content" />)

      await user.click(screen.getByRole('button'))

      // After clicking, shows copied state
      expect(screen.getByRole('button')).toHaveAttribute('aria-label', 'Copied')

      // Advance past the 2-second timeout
      vi.advanceTimersByTime(2000)

      // Should revert back to default label
      expect(screen.getByRole('button')).toHaveAttribute('aria-label', 'Copy')

      vi.useRealTimers()
    })
  })

  describe('error handling', () => {
    test('handles clipboard API failure gracefully', async () => {
      const user = userEvent.setup()
      vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(new Error('Not allowed'))

      render(<CopyButton text="test content" />)

      // Should not throw when clipboard fails
      await user.click(screen.getByRole('button'))

      const button = screen.getByRole('button')
      expect(button).toBeInTheDocument()
    })
  })

  describe('accessibility', () => {
    test('button has accessible label', () => {
      render(<CopyButton text="copy me" label="Copy Rules" />)

      const button = screen.getByRole('button')
      expect(button).toHaveAttribute('aria-label', 'Copy Rules')
    })
  })
})
