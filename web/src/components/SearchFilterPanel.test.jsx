import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, beforeEach, afterEach } from 'vitest'
import SearchFilterPanel from './SearchFilterPanel'

describe('SearchFilterPanel', () => {
  let user

  beforeEach(() => {
    user = userEvent.setup()
    localStorage.clear()
  })

  afterEach(() => {
    localStorage.clear()
  })

  describe('rendering', () => {
    test('renders header with default title when showSearch is true', () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
        />
      )

      expect(screen.getByText('Search & Filters')).toBeInTheDocument()
    })

    test('renders header with "Filters" title when showSearch is false', () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
          showSearch={false}
        />
      )

      expect(screen.getByText('Filters')).toBeInTheDocument()
    })

    test('renders search input when showSearch is true', () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
        />
      )

      // Panel starts collapsed, expand it first
      const header = screen.getByText('Search & Filters')
      expect(header).toBeInTheDocument()
    })

    test('does not render search input when showSearch is false', () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
          showSearch={false}
        />
      )

      expect(screen.queryByLabelText('Search')).not.toBeInTheDocument()
    })
  })

  describe('collapse/expand', () => {
    test('starts collapsed by default (no saved state)', () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
        />
      )

      // The search input is only rendered when expanded
      expect(screen.queryByPlaceholderText('Search...')).not.toBeInTheDocument()
    })

    test('expands when header is clicked', async () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
        />
      )

      await user.click(screen.getByText('Search & Filters'))

      expect(screen.getByPlaceholderText('Search...')).toBeInTheDocument()
    })

    test('toggles chevron icon direction', async () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
        />
      )

      const header = screen.getByText('Search & Filters').closest('button')

      // Collapsed: ChevronDown (aria-expanded=false)
      expect(header).toHaveAttribute('aria-expanded', 'false')

      await user.click(header)

      // Expanded: ChevronUp (aria-expanded=true)
      expect(header).toHaveAttribute('aria-expanded', 'true')
    })

    test('persists expanded state to localStorage', async () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
        />
      )

      await user.click(screen.getByText('Search & Filters'))

      expect(localStorage.getItem('test-key')).toBe('true')
    })

    test('reads initial expanded state from localStorage', () => {
      localStorage.setItem('test-key', 'true')

      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
        />
      )

      expect(screen.getByPlaceholderText('Search...')).toBeInTheDocument()
    })
  })

  describe('filter chips', () => {
    test('renders filter chips when provided and expanded', async () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
          filterChips={<button type="button">Active Filter</button>}
        />
      )

      await user.click(screen.getByText('Search & Filters'))

      expect(screen.getByText('Active Filter')).toBeInTheDocument()
    })
  })

  describe('active filters badge', () => {
    test('shows Active badge when hasActiveFilters is true', () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
          hasActiveFilters={true}
        />
      )

      expect(screen.getByText('Active')).toBeInTheDocument()
    })

    test('hides Active badge when hasActiveFilters is false', () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
          hasActiveFilters={false}
        />
      )

      expect(screen.queryByText('Active')).not.toBeInTheDocument()
    })
  })

  describe('rows per page', () => {
    test('renders rows per page select when value and onChange are provided', async () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
          rowsPerPage={25}
          onRowsPerPageChange={() => {}}
        />
      )

      await user.click(screen.getByText('Search & Filters'))

      expect(screen.getByLabelText('Rows per page')).toBeInTheDocument()
    })

    test('does not render rows per page when rightContent is provided', async () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
          rowsPerPage={25}
          onRowsPerPageChange={() => {}}
          rightContent={<button type="button">Action</button>}
        />
      )

      await user.click(screen.getByText('Search & Filters'))

      // Rows per page should not render when rightContent is present
      expect(screen.queryByLabelText('Rows per page')).not.toBeInTheDocument()
    })
  })

  describe('horizontal layout mode', () => {
    test('renders filterContent when provided', async () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
          filterContent={<span>Inline filter</span>}
        />
      )

      await user.click(screen.getByText('Search & Filters'))

      expect(screen.getByText('Inline filter')).toBeInTheDocument()
    })

    test('renders rightContent when provided', async () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
          rightContent={<button type="button">Action</button>}
        />
      )

      await user.click(screen.getByText('Search & Filters'))

      expect(screen.getByRole('button', { name: 'Action' })).toBeInTheDocument()
    })
  })

  describe('children', () => {
    test('renders children when expanded', async () => {
      render(
        <SearchFilterPanel
          storageKey="test-key"
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
        >
          <div>Extra content</div>
        </SearchFilterPanel>
      )

      await user.click(screen.getByText('Search & Filters'))

      expect(screen.getByText('Extra content')).toBeInTheDocument()
    })
  })
})
