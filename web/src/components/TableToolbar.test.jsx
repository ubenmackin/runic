import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import TableToolbar from './TableToolbar'

describe('TableToolbar', () => {
  describe('rendering', () => {
    test('renders search input with default placeholder', () => {
      render(
        <TableToolbar
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
        />
      )

      expect(screen.getByPlaceholderText('Search...')).toBeInTheDocument()
    })

    test('renders search input with custom placeholder', () => {
      render(
        <TableToolbar
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
          placeholder="Find logs..."
        />
      )

      expect(screen.getByPlaceholderText('Find logs...')).toBeInTheDocument()
    })

    test('renders rows per page select when value and onChange are provided', () => {
      render(
        <TableToolbar
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
          rowsPerPage={25}
          onRowsPerPageChange={() => {}}
        />
      )

      expect(screen.getByLabelText('Rows per page')).toBeInTheDocument()
    })

    test('renders children when provided', () => {
      render(
        <TableToolbar
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
        >
          <button type="button">Extra Action</button>
        </TableToolbar>
      )

      expect(screen.getByRole('button', { name: 'Extra Action' })).toBeInTheDocument()
    })
  })

  describe('search interaction', () => {
    test('calls onSearchChange when typing in search input', async () => {
      const user = userEvent.setup()
      const handleSearchChange = vi.fn()

      render(
        <TableToolbar
          searchTerm=""
          onSearchChange={handleSearchChange}
          onClearSearch={() => {}}
        />
      )

      const input = screen.getByPlaceholderText('Search...')
      await user.type(input, 'test')

      expect(handleSearchChange).toHaveBeenCalled()
    })

    test('shows clear button when search term exists', () => {
      render(
        <TableToolbar
          searchTerm="something"
          onSearchChange={() => {}}
          onClearSearch={() => {}}
        />
      )

      expect(screen.getByLabelText('Clear search')).toBeInTheDocument()
    })

    test('hides clear button when search term is empty', () => {
      render(
        <TableToolbar
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
        />
      )

      expect(screen.queryByLabelText('Clear search')).not.toBeInTheDocument()
    })

    test('calls onClearSearch when clear button is clicked', async () => {
      const user = userEvent.setup()
      const handleClear = vi.fn()

      render(
        <TableToolbar
          searchTerm="something"
          onSearchChange={() => {}}
          onClearSearch={handleClear}
        />
      )

      await user.click(screen.getByLabelText('Clear search'))
      expect(handleClear).toHaveBeenCalledTimes(1)
    })
  })

  describe('rows per page interaction', () => {
    test('calls onRowsPerPageChange when select value changes', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()

      render(
        <TableToolbar
          searchTerm=""
          onSearchChange={() => {}}
          onClearSearch={() => {}}
          rowsPerPage={10}
          onRowsPerPageChange={handleChange}
        />
      )

      const select = screen.getByLabelText('Rows per page')
      await user.selectOptions(select, '50')

      expect(handleChange).toHaveBeenCalledWith(50)
    })
  })
})
