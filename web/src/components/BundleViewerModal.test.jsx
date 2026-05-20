import { render, screen } from '@testing-library/react'

import { describe, test, expect, vi } from 'vitest'
import BundleViewerModal from './BundleViewerModal'

// Mock the API client
vi.mock('../api/client', () => ({
  api: {
    get: vi.fn().mockResolvedValue({
      rules: 'iptables -A INPUT -s 10.0.0.1 -j ACCEPT',
      version_number: 42,
      version: 'v42-abc',
    }),
  },
}))

// Mock the toast context
vi.mock('../hooks/ToastContext', () => ({
  useToastContext: () => vi.fn(),
}))

// Mock the diff utility
vi.mock('../utils/diff', () => ({
  computeDiff: vi.fn((oldRules, newRules) => `--- diff ---\n${oldRules}\n${newRules}`),
}))

describe('BundleViewerModal', () => {
  const defaultProps = {
    isOpen: true,
    onClose: vi.fn(),
    peerId: 1,
    peerHostname: 'test-peer',
    viewingPendingRules: false,
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('rendering', () => {
    test('returns null when isOpen is false', () => {
      const { container } = render(
        <BundleViewerModal {...defaultProps} isOpen={false} />
      )

      expect(container.innerHTML).toBe('')
    })

    test('renders modal when isOpen is true', () => {
      render(<BundleViewerModal {...defaultProps} />)

      expect(screen.getByText('Deployed Rules: test-peer')).toBeInTheDocument()
    })

    test('renders pending rules title when viewingPendingRules is true', () => {
      render(<BundleViewerModal {...defaultProps} viewingPendingRules={true} />)

      expect(screen.getByText('Pending Rules: test-peer')).toBeInTheDocument()
    })

    test('renders close button', () => {
      render(<BundleViewerModal {...defaultProps} />)

      // There are two close-like buttons: X and Close
      const closeButtons = screen.getAllByRole('button')
      expect(closeButtons.length).toBeGreaterThanOrEqual(1)
    })

    test('renders Close footer button', () => {
      render(<BundleViewerModal {...defaultProps} />)

      expect(screen.getByRole('button', { name: /close/i })).toBeInTheDocument()
    })
  })

  describe('loading state', () => {
    test('shows loading spinner while fetching', async () => {
      const { api } = await import('../api/client')
      // Make API hang
      api.get.mockImplementation(() => new Promise(() => {}))

      render(<BundleViewerModal {...defaultProps} />)

      expect(screen.getByText('Fetching latest bundle...')).toBeInTheDocument()
    })
  })

  describe('keyboard interaction', () => {
    test('modal overlay has tabIndex for keyboard access', () => {
      render(<BundleViewerModal {...defaultProps} />)

      const overlay = document.querySelector('.fixed.inset-0')
      expect(overlay).toHaveAttribute('tabindex', '-1')
    })
  })

  describe('accessibility', () => {
    test('has heading structure', async () => {
      render(<BundleViewerModal {...defaultProps} />)

      const heading = screen.getByRole('heading', { level: 3 })
      expect(heading).toHaveTextContent('Deployed Rules: test-peer')
    })

    test('Close button is accessible', () => {
      render(<BundleViewerModal {...defaultProps} />)

      const closeButton = screen.getByRole('button', { name: /close/i })
      expect(closeButton).toBeInTheDocument()
    })
  })
})
