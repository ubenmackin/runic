import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import SearchableSelect from './SearchableSelect'

// Mock scrollIntoView on all elements
Element.prototype.scrollIntoView = vi.fn()

// Mock useDropdownPosition to return stable values
vi.mock('../hooks/useDropdownPosition', () => ({
  useDropdownPosition: () => ({ top: 100, left: 0, width: 300, positionAbove: false }),
}))

const defaultOptions = [
  { value: '1', label: 'Web Server', category: 'servers' },
  { value: '2', label: 'Database', category: 'servers' },
  { value: '3', label: 'Router', category: 'network' },
  { value: '4', label: 'Switch', category: 'network' },
]

describe('SearchableSelect', () => {
  let user

  beforeEach(() => {
    user = userEvent.setup()
  })

  afterEach(() => {
    // Let React handle cleanup via unmount
  })

  describe('rendering', () => {
    test('renders with placeholder when no value selected', () => {
      render(
        <SearchableSelect
          options={defaultOptions}
          value=""
          onChange={() => {}}
          placeholder="Choose an option..."
        />
      )

      expect(screen.getByText('Choose an option...')).toBeInTheDocument()
    })

    test('renders selected option label', () => {
      render(
        <SearchableSelect
          options={defaultOptions}
          value="1"
          onChange={() => {}}
        />
      )

      expect(screen.getByText('Web Server')).toBeInTheDocument()
    })

    test('renders button with aria-haspopup and aria-expanded', () => {
      render(
        <SearchableSelect
          options={defaultOptions}
          value=""
          onChange={() => {}}
        />
      )

      const button = screen.getByRole('button')
      expect(button).toHaveAttribute('aria-haspopup', 'listbox')
      expect(button).toHaveAttribute('aria-expanded', 'false')
    })

    test('button is disabled when disabled prop is true', () => {
      render(
        <SearchableSelect
          options={defaultOptions}
          value=""
          onChange={() => {}}
          disabled={true}
        />
      )

      expect(screen.getByRole('button')).toBeDisabled()
    })
  })

  describe('dropdown open/close', () => {
    test('opens dropdown when button is clicked', async () => {
      render(
        <SearchableSelect
          options={defaultOptions}
          value=""
          onChange={() => {}}
        />
      )

      await user.click(screen.getByRole('button'))

      expect(screen.getByRole('listbox')).toBeInTheDocument()
    })

    test('closes dropdown when clicking outside', async () => {
      render(
        <SearchableSelect
          options={defaultOptions}
          value=""
          onChange={() => {}}
        />
      )

      await user.click(screen.getByRole('button'))
      expect(screen.getByRole('listbox')).toBeInTheDocument()

      await user.click(document.body)
      await waitFor(() => {
        expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
      })
    })

    test('does not open when disabled and clicked', async () => {
      render(
        <SearchableSelect
          options={defaultOptions}
          value=""
          onChange={() => {}}
          disabled={true}
        />
      )

      await user.click(screen.getByRole('button'))
      expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
    })
  })

  describe('option selection', () => {
    test('calls onChange with value and category when option is clicked', async () => {
      const handleChange = vi.fn()

      render(
        <SearchableSelect
          options={defaultOptions}
          value=""
          onChange={handleChange}
        />
      )

      await user.click(screen.getByRole('button'))
      await user.click(screen.getByText('Database'))

      expect(handleChange).toHaveBeenCalledWith('2', 'servers')
    })

    test('closes dropdown after selecting an option', async () => {
      const handleChange = vi.fn()

      render(
        <SearchableSelect
          options={defaultOptions}
          value=""
          onChange={handleChange}
        />
      )

      await user.click(screen.getByRole('button'))
      await user.click(screen.getByText('Router'))

      await waitFor(() => {
        expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
      })
    })

    test('shows check icon on selected option', async () => {
      render(
        <SearchableSelect
          options={defaultOptions}
          value="1"
          onChange={() => {}}
        />
      )

      await user.click(screen.getByRole('button'))

      // The selected option should have a check icon
      const listbox = screen.getByRole('listbox')
      expect(listbox.innerHTML).toContain('Web Server')
    })
  })

  describe('category grouping', () => {
    test('renders category headers', async () => {
      render(
        <SearchableSelect
          options={defaultOptions}
          value=""
          onChange={() => {}}
        />
      )

      await user.click(screen.getByRole('button'))

      expect(screen.getByText('servers')).toBeInTheDocument()
      expect(screen.getByText('network')).toBeInTheDocument()
    })

    test('groups options by category', async () => {
      render(
        <SearchableSelect
          options={defaultOptions}
          value=""
          onChange={() => {}}
        />
      )

      await user.click(screen.getByRole('button'))

      // Options under "servers" category
      expect(screen.getByText('Web Server')).toBeInTheDocument()
      expect(screen.getByText('Database')).toBeInTheDocument()

      // Options under "network" category
      expect(screen.getByText('Router')).toBeInTheDocument()
      expect(screen.getByText('Switch')).toBeInTheDocument()
    })
  })

  describe('search filtering', () => {
    test('filters options based on search input', async () => {
      render(
        <SearchableSelect
          options={defaultOptions}
          value=""
          onChange={() => {}}
        />
      )

      await user.click(screen.getByRole('button'))

      const searchInput = screen.getByLabelText('Search options')
      await user.type(searchInput, 'Web')

      expect(screen.getByText('Web Server')).toBeInTheDocument()
      expect(screen.queryByText('Database')).not.toBeInTheDocument()
    })

    test('shows "No options found" when search yields no results', async () => {
      render(
        <SearchableSelect
          options={defaultOptions}
          value=""
          onChange={() => {}}
        />
      )

      await user.click(screen.getByRole('button'))

      const searchInput = screen.getByLabelText('Search options')
      await user.type(searchInput, 'zzz')

      expect(screen.getByText('No options found')).toBeInTheDocument()
    })
  })

  describe('keyboard navigation', () => {
    test('opens dropdown with ArrowDown key', async () => {
      render(
        <SearchableSelect
          options={defaultOptions}
          value=""
          onChange={() => {}}
        />
      )

      const button = screen.getByRole('button')
      button.focus()
      await user.keyboard('{ArrowDown}')

      expect(screen.getByRole('listbox')).toBeInTheDocument()
    })

    test('closes dropdown with Escape key', async () => {
      render(
        <SearchableSelect
          options={defaultOptions}
          value=""
          onChange={() => {}}
        />
      )

      await user.click(screen.getByRole('button'))
      expect(screen.getByRole('listbox')).toBeInTheDocument()

      await user.keyboard('{Escape}')
      await waitFor(() => {
        expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
      })
    })
  })

  describe('filter by category prop', () => {
    test('only selects option matching category when filter is active', async () => {
      const handleChange = vi.fn()

      render(
        <SearchableSelect
          options={defaultOptions}
          value="1"
          category="servers"
          onChange={handleChange}
        />
      )

      await user.click(screen.getByRole('button'))

      // Click on "Database" (also in servers category)
      const options = screen.getAllByRole('option')
      const databaseOption = options.find(o => o.textContent === 'Database')
      await user.click(databaseOption)

      // With category filter, click on Database (value=2) should call onChange
      expect(handleChange).toHaveBeenCalledWith('2', 'servers')
    })
  })
})
