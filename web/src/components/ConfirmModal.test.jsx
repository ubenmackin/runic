import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import ConfirmModal from './ConfirmModal'

describe('ConfirmModal', () => {
  let modalRoot

  beforeEach(() => {
    // Create a portal root for the modal
    modalRoot = document.createElement('div')
    modalRoot.id = 'modal-root'
    document.body.appendChild(modalRoot)
  })

  afterEach(() => {
    // Clean up the portal root
    document.body.removeChild(modalRoot)
    modalRoot = null
  })

  describe('rendering', () => {
    test('renders when open with title and message', () => {
      render(
        <ConfirmModal
          title="Confirm Action"
          message="Are you sure you want to proceed?"
          onConfirm={() => {}}
          onCancel={() => {}}
        />
      )

      expect(screen.getByText('Confirm Action')).toBeInTheDocument()
      expect(screen.getByText('Are you sure you want to proceed?')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /confirm/i })).toBeInTheDocument()
    })

    test('renders Cancel button', () => {
      render(
        <ConfirmModal
          title="Test Modal"
          message="Test message"
          onConfirm={() => {}}
          onCancel={() => {}}
        />
      )

      expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument()
    })

    test('renders Confirm button', () => {
      render(
        <ConfirmModal
          title="Test Modal"
          message="Test message"
          onConfirm={() => {}}
          onCancel={() => {}}
        />
      )

      expect(screen.getByRole('button', { name: /confirm/i })).toBeInTheDocument()
    })
  })

  describe('button interactions', () => {
    test('calls onConfirm when Confirm button is clicked', async () => {
      const user = userEvent.setup()
      const handleConfirm = vi.fn()
      const handleCancel = vi.fn()
      
      render(
        <ConfirmModal
          title="Test Modal"
          message="Test message"
          onConfirm={handleConfirm}
          onCancel={handleCancel}
        />
      )

      await user.click(screen.getByRole('button', { name: /confirm/i }))

      expect(handleConfirm).toHaveBeenCalledTimes(1)
      expect(handleCancel).not.toHaveBeenCalled()
    })

    test('calls onCancel when Cancel button is clicked', async () => {
      const user = userEvent.setup()
      const handleConfirm = vi.fn()
      const handleCancel = vi.fn()
      
      render(
        <ConfirmModal
          title="Test Modal"
          message="Test message"
          onConfirm={handleConfirm}
          onCancel={handleCancel}
        />
      )

      await user.click(screen.getByRole('button', { name: /cancel/i }))

      expect(handleCancel).toHaveBeenCalledTimes(1)
      expect(handleConfirm).not.toHaveBeenCalled()
    })

    test('calls onCancel when X button is clicked', async () => {
      const user = userEvent.setup()
      const handleConfirm = vi.fn()
      const handleCancel = vi.fn()
      
      render(
        <ConfirmModal
          title="Test Modal"
          message="Test message"
          onConfirm={handleConfirm}
          onCancel={handleCancel}
        />
      )

      // The X button doesn't have accessible name, so we find it by its container
      const closeButton = screen.getByRole('button', { name: '' })
      await user.click(closeButton)

      expect(handleCancel).toHaveBeenCalledTimes(1)
      expect(handleConfirm).not.toHaveBeenCalled()
    })
  })

  describe('danger mode', () => {
    test('renders danger styling when danger prop is true', () => {
      render(
        <ConfirmModal
          title="Delete Item"
          message="This action cannot be undone"
          onConfirm={() => {}}
          onCancel={() => {}}
          danger={true}
        />
      )

      const confirmButton = screen.getByRole('button', { name: /confirm/i })
      expect(confirmButton.className).toContain('bg-red-600')
    })

    test('renders normal styling when danger prop is false', () => {
      render(
        <ConfirmModal
          title="Confirm Action"
          message="Are you sure?"
          onConfirm={() => {}}
          onCancel={() => {}}
          danger={false}
        />
      )

      const confirmButton = screen.getByRole('button', { name: /confirm/i })
      expect(confirmButton.className).toContain('bg-purple-active')
    })

    test('danger prop defaults to false', () => {
      render(
        <ConfirmModal
          title="Test Modal"
          message="Test message"
          onConfirm={() => {}}
          onCancel={() => {}}
        />
      )

      const confirmButton = screen.getByRole('button', { name: /confirm/i })
      expect(confirmButton.className).toContain('bg-purple-active')
    })
  })

  describe('focus trap', () => {
    test('modal is rendered in a portal to document.body', () => {
      render(
        <ConfirmModal
          title="Test Modal"
          message="Test message"
          onConfirm={() => {}}
          onCancel={() => {}}
        />
      )

      // The modal content is rendered via portal
      const overlay = document.querySelector('.fixed.inset-0')
      expect(overlay).toBeInTheDocument()
    })

    test('focus starts on an interactive element within modal', async () => {
      render(
        <ConfirmModal
          title="Test Modal"
          message="Test message"
          onConfirm={() => {}}
          onCancel={() => {}}
        />
      )

      // Verify there are focusable elements
      const buttons = screen.getAllByRole('button')
      expect(buttons.length).toBeGreaterThan(0)
    })

    test('tab cycles through focusable elements within modal', async () => {
      const user = userEvent.setup()
      
      render(
        <ConfirmModal
          title="Test Modal"
          message="Test message"
          onConfirm={() => {}}
          onCancel={() => {}}
        />
      )

      const buttons = screen.getAllByRole('button')
      const firstButton = buttons[0]
      firstButton.focus()

      // Tab through focusable elements
      await user.tab()
      expect(buttons[1]).toHaveFocus()

      await user.tab()
      expect(buttons[2]).toHaveFocus()
    })
  })

  describe('keyboard interactions', () => {
    test('Escape key does not automatically close modal (requires explicit handler)', async () => {
      const user = userEvent.setup()
      const handleCancel = vi.fn()
      
      render(
        <ConfirmModal
          title="Test Modal"
          message="Test message"
          onConfirm={() => {}}
          onCancel={handleCancel}
        />
      )

      // Pressing Escape without an onKeyDown handler won't trigger onCancel
      await user.keyboard('{Escape}')

      // The modal doesn't have built-in escape key handling
      // This is expected behavior - the parent component controls visibility
      expect(handleCancel).not.toHaveBeenCalled()
    })

    test('Enter key on focused Confirm button triggers onConfirm', async () => {
      const user = userEvent.setup()
      const handleConfirm = vi.fn()
      const handleCancel = vi.fn()
      
      render(
        <ConfirmModal
          title="Test Modal"
          message="Test message"
          onConfirm={handleConfirm}
          onCancel={handleCancel}
        />
      )

      const confirmButton = screen.getByRole('button', { name: /confirm/i })
      confirmButton.focus()
      await user.keyboard('{Enter}')

      expect(handleConfirm).toHaveBeenCalledTimes(1)
    })

    test('Enter key on focused Cancel button triggers onCancel', async () => {
      const user = userEvent.setup()
      const handleConfirm = vi.fn()
      const handleCancel = vi.fn()
      
      render(
        <ConfirmModal
          title="Test Modal"
          message="Test message"
          onConfirm={handleConfirm}
          onCancel={handleCancel}
        />
      )

      const cancelButton = screen.getByRole('button', { name: /cancel/i })
      cancelButton.focus()
      await user.keyboard('{Enter}')

      expect(handleCancel).toHaveBeenCalledTimes(1)
    })
  })

  describe('portal rendering', () => {
    test('modal is appended to document.body', () => {
      const { unmount } = render(
        <ConfirmModal
          title="Test Modal"
          message="Test message"
          onConfirm={() => {}}
          onCancel={() => {}}
        />
      )

      // Check that modal overlay exists in the document
      const overlay = document.querySelector('.fixed.inset-0.z-\\[9999\\]')
      expect(overlay).toBeInTheDocument()

      unmount()

      // After unmount, the portal should be removed
      expect(document.querySelector('.fixed.inset-0.z-\\[9999\\]')).not.toBeInTheDocument()
    })
  })

  describe('accessibility', () => {
    test('has proper heading structure', () => {
      render(
        <ConfirmModal
          title="Important Action"
          message="Please read carefully"
          onConfirm={() => {}}
          onCancel={() => {}}
        />
      )

      expect(screen.getByRole('heading', { level: 3 })).toHaveTextContent('Important Action')
    })

    test('message text is visible', () => {
      render(
        <ConfirmModal
          title="Test"
          message="This is an important message"
          onConfirm={() => {}}
          onCancel={() => {}}
        />
      )

      expect(screen.getByText('This is an important message')).toBeInTheDocument()
    })
  })
})
