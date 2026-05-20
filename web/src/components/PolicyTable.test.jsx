import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import PolicyTable from './PolicyTable'

// Mock ToggleSwitch
vi.mock('./ToggleSwitch', () => ({
  default: ({ checked, onChange, 'aria-labelledby': ariaLabelledBy }) => (
    <button
      role="switch"
      aria-checked={checked}
      aria-labelledby={ariaLabelledBy}
      onClick={() => onChange(!checked)}
      data-testid="mock-toggle-switch"
    />
  ),
}))

// Mock SortIndicator
vi.mock('./SortIndicator', () => ({
  default: () => <span data-testid="mock-sort-indicator" />,
}))

// Mock Pagination
vi.mock('./Pagination', () => ({
  default: () => <div data-testid="mock-pagination">Pagination</div>,
}))

// Mock EmptyState
vi.mock('./EmptyState', () => ({
  default: ({ title, message, action, onAction }) => (
    <div data-testid="mock-empty-state">
      <span>{title}</span>
      <span>{message}</span>
      {action && <button onClick={onAction}>{action}</button>}
    </div>
  ),
}))

// Mock KebabMenu
vi.mock('./KebabMenu', () => ({
  default: ({ items }) => (
    <div data-testid="mock-kebab-menu">
      {items.map((item, i) => (
        <button key={i} onClick={item.onClick} data-testid={`kebab-item-${i}`}>
          {item.label}
        </button>
      ))}
    </div>
  ),
}))

describe('PolicyTable', () => {
  const policies = [
    {
      id: 1,
      name: 'allow-ssh',
      enabled: true,
      priority: 100,
      source_type: 'peer',
      source_id: 1,
      source_ip: null,
      target_type: 'peer',
      target_id: 2,
      target_ip: null,
      service_id: 1,
      action: 'ACCEPT',
      direction: 'forward',
      is_pending_delete: false,
    },
    {
      id: 2,
      name: 'block-telnet',
      enabled: false,
      priority: 200,
      source_type: 'group',
      source_id: 1,
      source_ip: null,
      target_type: 'peer',
      target_id: 3,
      target_ip: null,
      service_id: 2,
      action: 'LOG_DROP',
      direction: 'both',
      is_pending_delete: false,
    },
  ]

  const defaultProps = {
    policies,
    paginatedPolicies: policies,
    sortConfig: { key: 'name', direction: 'asc' },
    onSort: vi.fn(),
    onEdit: vi.fn(),
    onDelete: vi.fn(),
    canEdit: true,
    searchTerm: '',
    showPendingDeletes: false,
    setShowPendingDeletes: vi.fn(),
    toggleMutation: { mutate: vi.fn() },
    getEntityName: vi.fn((type, id) => `Entity ${id}`),
    getServiceName: vi.fn((id) => `Service ${id}`),
    openAdd: vi.fn(),
    showingRange: '1-2 of 2',
    page: 1,
    totalPages: 1,
    onPageChange: vi.fn(),
    totalItems: 2,
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('empty states', () => {
    test('renders empty state when no policies and no search term', () => {
      render(
        <PolicyTable
          {...defaultProps}
          policies={[]}
          paginatedPolicies={[]}
        />
      )

      expect(screen.getByTestId('mock-empty-state')).toBeInTheDocument()
      expect(screen.getByText('No policies yet')).toBeInTheDocument()
    })

    test('renders no-match message when paginatedPolicies is empty with search term', () => {
      render(
        <PolicyTable
          {...defaultProps}
          paginatedPolicies={[]}
          searchTerm="ssh"
        />
      )

      expect(screen.getByText('No policies match your search.')).toBeInTheDocument()
    })
  })

  describe('pending deletes', () => {
    test('shows pending deletes checkbox when policies have pending deletes', () => {
      const policiesWithDelete = [
        { ...policies[0], is_pending_delete: true },
      ]

      render(
        <PolicyTable
          {...defaultProps}
          policies={policiesWithDelete}
          paginatedPolicies={policiesWithDelete}
        />
      )

      expect(screen.getByText('Show Pending Deletes')).toBeInTheDocument()
    })

    test('does not show pending deletes checkbox when no pending deletes', () => {
      render(<PolicyTable {...defaultProps} />)

      expect(screen.queryByText('Show Pending Deletes')).not.toBeInTheDocument()
    })
  })

  describe('table rendering', () => {
    test('renders policy names', () => {
      render(<PolicyTable {...defaultProps} />)

      // Policy names appear in both mobile and desktop views, so use getAllByText
      expect(screen.getAllByText('allow-ssh').length).toBeGreaterThanOrEqual(1)
      expect(screen.getAllByText('block-telnet').length).toBeGreaterThanOrEqual(1)
    })

    test('renders action badges', () => {
      render(<PolicyTable {...defaultProps} />)

      expect(screen.getByText('ACCEPT')).toBeInTheDocument()
      expect(screen.getByText('LOG_DROP')).toBeInTheDocument()
    })

    test('renders entity names via getEntityName', () => {
      render(<PolicyTable {...defaultProps} />)

      expect(defaultProps.getEntityName).toHaveBeenCalled()
    })

    test('renders service names via getServiceName', () => {
      render(<PolicyTable {...defaultProps} />)

      expect(defaultProps.getServiceName).toHaveBeenCalled()
    })
  })

  describe('interactions', () => {
    test('calls onSort when column header is clicked', async () => {
      const user = userEvent.setup()
      const handleSort = vi.fn()

      render(<PolicyTable {...defaultProps} onSort={handleSort} />)

      const sortButtons = screen.getAllByRole('button', { name: /name/i })
      await user.click(sortButtons[0])

      expect(handleSort).toHaveBeenCalledWith('name')
    })
  })

  describe('accessibility', () => {
    test('pending delete checkbox has proper id and label', () => {
      const policiesWithDelete = [
        { ...policies[0], is_pending_delete: true },
      ]

      render(
        <PolicyTable
          {...defaultProps}
          policies={policiesWithDelete}
          paginatedPolicies={policiesWithDelete}
        />
      )

      const checkbox = screen.getByRole('checkbox')
      expect(checkbox).toHaveAttribute('id', 'showPendingDeletes')
    })
  })
})
