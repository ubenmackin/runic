import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

import PendingChangesModal from './PendingChangesModal'

// Mock the API client
vi.mock('../api/client', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
  },
}))

import { api } from '../api/client'

// Mock ToastContext
const mockShowToast = vi.fn()
vi.mock('../hooks/ToastContext', () => ({
  useToastContext: () => mockShowToast,
}))

// Mock useFocusTrap
vi.mock('../hooks/useFocusTrap', () => ({
  useFocusTrap: vi.fn(),
}))

// Mock ConfirmModal
vi.mock('./ConfirmModal', () => ({
  default: ({ title, message, onConfirm, onCancel, danger }) => (
    <div data-testid="confirm-modal">
      <div>{title}</div>
      <div>{message}</div>
      <button onClick={onConfirm} data-testid="confirm-yes">
        Confirm
      </button>
      <button onClick={onCancel} data-testid="confirm-no">
        Cancel
      </button>
      {danger && <span data-testid="danger-flag" />}
    </div>
  ),
}))

// Mock CopyButton
vi.mock('./CopyButton', () => ({
  default: ({ text, label }) => (
    <button data-testid="copy-button" data-text={text}>
      {label}
    </button>
  ),
}))

const sampleChanges = [
  {
    id: 1,
    change_type: 'policy',
    change_id: 'rule-1',
    entity_name: 'allow-https',
    change_action: 'create',
    change_summary: 'Add allow-https policy',
  },
  {
    id: 2,
    change_type: 'policy',
    change_id: 'rule-1',
    entity_name: 'allow-https',
    change_action: 'update',
    change_summary: 'Update action to ACCEPT',
  },
  {
    id: 3,
    change_type: 'group',
    change_id: 'group-1',
    entity_name: 'web-servers',
    change_action: 'create',
    change_summary: 'Create web-servers group',
  },
]

describe('PendingChangesModal', () => {
  let user

  beforeEach(() => {
    vi.clearAllMocks()
    user = userEvent.setup()
  })

  afterEach(() => {
    document.body.innerHTML = ''
  })

  describe('loading state', () => {
    test('shows loading spinner while fetching changes', () => {
      api.get.mockImplementation(() => new Promise(() => {}))

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={() => {}}
          onApplied={() => {}}
        />
      )

      expect(screen.getByText('Loading pending changes...')).toBeInTheDocument()
    })
  })

  describe('error state', () => {
    test('shows error message when fetch fails', async () => {
      api.get.mockRejectedValue({ message: 'Failed to load changes' })

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={() => {}}
          onApplied={() => {}}
        />
      )

      await waitFor(() => {
        expect(
          screen.getByText('Failed to load changes')
        ).toBeInTheDocument()
      })
    })
  })

  describe('empty state', () => {
    test('shows empty message when no changes', async () => {
      api.get
        .mockResolvedValueOnce({ changes: [] })
        .mockResolvedValueOnce({ rules: '' })

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={() => {}}
          onApplied={() => {}}
        />
      )

      await waitFor(() => {
        expect(
          screen.getByText('No pending changes for this peer.')
        ).toBeInTheDocument()
      })
    })
  })

  describe('rendering with data', () => {
    test('renders modal title with peer hostname', async () => {
      api.get
        .mockResolvedValueOnce({ changes: sampleChanges })
        .mockResolvedValueOnce({ rules: '' })

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={() => {}}
          onApplied={() => {}}
        />
      )

      await waitFor(() => {
        expect(
          screen.getByText('Changes for Review: test-peer')
        ).toBeInTheDocument()
      })
    })

    test('renders tabs when changes are present', async () => {
      api.get
        .mockResolvedValueOnce({ changes: sampleChanges })
        .mockResolvedValueOnce({ rules: '' })
      api.post.mockResolvedValue({
        current_version_number: 5,
        new_version_number: 6,
        rules_content: 'new rules',
      })

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={() => {}}
          onApplied={() => {}}
        />
      )

      await waitFor(() => {
        expect(screen.getByText('Queued Changes')).toBeInTheDocument()
        expect(screen.getByText('Bundle Preview')).toBeInTheDocument()
      })
    })

    test('renders queued changes in table', async () => {
      api.get
        .mockResolvedValueOnce({ changes: sampleChanges })
        .mockResolvedValueOnce({ rules: '' })
      api.post.mockResolvedValue({
        current_version_number: 5,
        new_version_number: 6,
        rules_content: 'new rules',
      })

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={() => {}}
          onApplied={() => {}}
        />
      )

      await waitFor(() => {
        expect(screen.getByText('Queued Changes (3)')).toBeInTheDocument()
        expect(screen.getByText('allow-https')).toBeInTheDocument()
        expect(screen.getByText('web-servers')).toBeInTheDocument()
      })
    })

    test('renders action badges for changes', async () => {
      api.get
        .mockResolvedValueOnce({ changes: sampleChanges })
        .mockResolvedValueOnce({ rules: '' })
      api.post.mockResolvedValue({
        current_version_number: 5,
        new_version_number: 6,
        rules_content: 'new rules',
      })

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={() => {}}
          onApplied={() => {}}
        />
      )

      await waitFor(() => {
        const createdBadges = screen.getAllByText('Created')
        expect(createdBadges.length).toBeGreaterThanOrEqual(1)
        expect(screen.getByText('Updated')).toBeInTheDocument()
      })
    })

    test('renders Apply and Rollback buttons per entity', async () => {
      api.get
        .mockResolvedValueOnce({ changes: sampleChanges })
        .mockResolvedValueOnce({ rules: '' })
      api.post.mockResolvedValue({
        current_version_number: 5,
        new_version_number: 6,
        rules_content: 'new rules',
      })

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={() => {}}
          onApplied={() => {}}
        />
      )

      await waitFor(() => {
        const applyButtons = screen.getAllByText('✓ Apply')
        const rollbackButtons = screen.getAllByText('↩ Rollback')
        expect(applyButtons.length).toBeGreaterThan(0)
        expect(rollbackButtons.length).toBeGreaterThan(0)
      })
    })
  })

  describe('preview and diff', () => {
    test('auto-generates preview when changes are loaded', async () => {
      api.get
        .mockResolvedValueOnce({ changes: sampleChanges })
        .mockResolvedValueOnce({ rules: 'old rules content' })

      api.post.mockResolvedValue({
        current_version_number: 5,
        new_version_number: 6,
        rules_content: 'new rules content',
      })

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={() => {}}
          onApplied={() => {}}
        />
      )

      await waitFor(() => {
        expect(api.post).toHaveBeenCalledWith('/pending-changes/1/preview')
      })
    })

    test('shows preview loading state', async () => {
      api.get
        .mockResolvedValueOnce({ changes: sampleChanges })
        .mockResolvedValueOnce({ rules: '' })

      // Post never resolves (loading)
      api.post.mockImplementation(() => new Promise(() => {}))

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={() => {}}
          onApplied={() => {}}
        />
      )

      await waitFor(() => {
        expect(screen.getByText('Generating diff...')).toBeInTheDocument()
      })
    })

    test('shows Copy Diff button when diff is available', async () => {
      api.get
        .mockResolvedValueOnce({ changes: sampleChanges })
        .mockResolvedValueOnce({ rules: '' })

      api.post.mockResolvedValue({
        current_version_number: 5,
        new_version_number: 6,
        rules_content: 'new rules',
      })

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={() => {}}
          onApplied={() => {}}
        />
      )

      await waitFor(() => {
        expect(screen.getByTestId('copy-button')).toBeInTheDocument()
      })
    })
  })

  describe('bundle preview tab', () => {
    test('switches to bundle preview tab', async () => {
      api.get
        .mockResolvedValueOnce({ changes: sampleChanges })
        .mockResolvedValueOnce({ rules: '' })

      api.post.mockResolvedValue({
        current_version_number: 5,
        new_version_number: 6,
        rules_content: 'new rules content',
      })

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={() => {}}
          onApplied={() => {}}
        />
      )

      await waitFor(() => {
        expect(screen.getByText('Bundle Preview')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Bundle Preview'))

      await waitFor(() => {
        expect(screen.getByText('Current Version:')).toBeInTheDocument()
        expect(screen.getByText('New Version:')).toBeInTheDocument()
      })
    })
  })

  describe('apply changes', () => {
    test('calls apply API when Apply Changes is clicked', async () => {
      api.get
        .mockResolvedValueOnce({ changes: sampleChanges })
        .mockResolvedValueOnce({ rules: '' })

      api.post
        .mockResolvedValueOnce({
          current_version_number: 5,
          new_version_number: 6,
          rules_content: 'new rules',
        })
        .mockResolvedValueOnce({})

      const handleApplied = vi.fn()
      const handleClose = vi.fn()

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={handleClose}
          onApplied={handleApplied}
        />
      )

      await waitFor(() => {
        expect(screen.getByText('Apply Changes')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Apply Changes'))

      await waitFor(() => {
        expect(api.post).toHaveBeenCalledWith('/pending-changes/1/apply')
        expect(mockShowToast).toHaveBeenCalledWith(
          'Changes applied successfully',
          'success'
        )
        expect(handleApplied).toHaveBeenCalled()
        expect(handleClose).toHaveBeenCalled()
      })
    })

    test('shows error toast when apply fails', async () => {
      api.get
        .mockResolvedValueOnce({ changes: sampleChanges })
        .mockResolvedValueOnce({ rules: '' })

      api.post
        .mockResolvedValueOnce({
          current_version_number: 5,
          new_version_number: 6,
          rules_content: 'new rules',
        })
        .mockRejectedValue({ message: 'Apply failed' })

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={() => {}}
          onApplied={() => {}}
        />
      )

      await waitFor(() => {
        expect(screen.getByText('Apply Changes')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Apply Changes'))

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith(
          'Failed to apply changes: Apply failed',
          'error'
        )
      })
    })
  })

  describe('discard all', () => {
    test('shows confirm modal when Discard All is clicked', async () => {
      api.get
        .mockResolvedValueOnce({ changes: sampleChanges })
        .mockResolvedValueOnce({ rules: '' })

      api.post.mockResolvedValue({
        current_version_number: 5,
        new_version_number: 6,
        rules_content: 'new rules',
      })

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={() => {}}
          onApplied={() => {}}
        />
      )

      await waitFor(() => {
        expect(screen.getByText('Discard All')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Discard All'))

      expect(
        screen.getByText('Discard All Pending Changes?')
      ).toBeInTheDocument()
    })

    test('calls rollback API when confirmed', async () => {
      api.get
        .mockResolvedValueOnce({ changes: sampleChanges })
        .mockResolvedValueOnce({ rules: '' })

      api.post
        .mockResolvedValueOnce({
          current_version_number: 5,
          new_version_number: 6,
          rules_content: 'new rules',
        })
        .mockResolvedValueOnce({})

      const handleApplied = vi.fn()
      const handleClose = vi.fn()

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={handleClose}
          onApplied={handleApplied}
        />
      )

      await waitFor(() => {
        expect(screen.getByText('Discard All')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Discard All'))

      await user.click(screen.getByTestId('confirm-yes'))

      await waitFor(() => {
        expect(api.post).toHaveBeenCalledWith('/pending-changes/rollback')
        expect(mockShowToast).toHaveBeenCalledWith(
          'All pending changes discarded successfully',
          'success'
        )
      })
    })
  })

  describe('close button', () => {
    test('calls onClose when Close button is clicked', async () => {
      api.get
        .mockResolvedValueOnce({ changes: [] })
        .mockResolvedValueOnce({ rules: '' })

      const handleClose = vi.fn()

      render(
        <PendingChangesModal
          peerId={1}
          peerHostname="test-peer"
          onClose={handleClose}
          onApplied={() => {}}
        />
      )

      await waitFor(() => {
        expect(screen.getByText('Close')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Close'))

      expect(handleClose).toHaveBeenCalled()
    })
  })
})
