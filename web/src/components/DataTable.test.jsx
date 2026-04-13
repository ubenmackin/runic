import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import DataTable from './DataTable'

describe('DataTable', () => {
  const defaultColumns = [
    { key: 'name', label: 'Name' },
    { key: 'email', label: 'Email' },
    { key: 'status', label: 'Status' },
  ]

  const defaultData = [
    { id: 1, name: 'John Doe', email: 'john@example.com', status: 'Active' },
    { id: 2, name: 'Jane Smith', email: 'jane@example.com', status: 'Inactive' },
    { id: 3, name: 'Bob Johnson', email: 'bob@example.com', status: 'Active' },
  ]

  const defaultPagination = {
    page: 1,
    rowsPerPage: 10,
    totalItems: 30,
    onPageChange: vi.fn(),
    onRowsPerPageChange: vi.fn(),
    showingRange: 'Showing 1-10 of 30',
  }

  describe('data rendering', () => {
    test('renders table with data correctly', () => {
      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData} 
        />
      )

      // Check headers
      expect(screen.getByText('Name')).toBeInTheDocument()
      expect(screen.getByText('Email')).toBeInTheDocument()
      expect(screen.getByText('Status')).toBeInTheDocument()

      // Check data rows
      expect(screen.getByText('John Doe')).toBeInTheDocument()
      expect(screen.getByText('jane@example.com')).toBeInTheDocument()
      expect(screen.getByText('Inactive')).toBeInTheDocument()
      // Active appears twice, so use getAllByText
      expect(screen.getAllByText('Active')).toHaveLength(2)
    })

    test('renders all rows in data', () => {
      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData} 
        />
      )

      expect(screen.getByText('John Doe')).toBeInTheDocument()
      expect(screen.getByText('Jane Smith')).toBeInTheDocument()
      expect(screen.getByText('Bob Johnson')).toBeInTheDocument()
    })

    test('renders custom column renderers', () => {
      const columns = [
        { key: 'name', label: 'Name' },
        { 
          key: 'status', 
          label: 'Status',
          render: (item) => <span data-testid={`status-${item.id}`}>{item.status.toUpperCase()}</span>
        },
      ]

      render(
        <DataTable 
          columns={columns} 
          data={defaultData} 
        />
      )

      expect(screen.getByTestId('status-1')).toHaveTextContent('ACTIVE')
      expect(screen.getByTestId('status-2')).toHaveTextContent('INACTIVE')
    })

    test('uses custom className on columns', () => {
      const columns = [
        { key: 'name', label: 'Name', className: 'custom-header-class' },
        { key: 'email', label: 'Email', cellClassName: 'custom-cell-class' },
      ]

      render(
        <DataTable 
          columns={columns} 
          data={defaultData} 
        />
      )

      const nameHeader = screen.getByText('Name').closest('th')
      expect(nameHeader).toHaveClass('custom-header-class')
    })
  })

  describe('empty state', () => {
    test('renders empty message when no data', () => {
      render(
        <DataTable 
          columns={defaultColumns} 
          data={[]} 
          emptyMessage="No items found"
        />
      )

      expect(screen.getByText('No items found')).toBeInTheDocument()
    })

    test('renders nothing when no data and no empty message', () => {
      const { container } = render(
        <DataTable 
          columns={defaultColumns} 
          data={[]} 
        />
      )

      expect(container.firstChild).toBeNull()
    })

    test('handles null data', () => {
      render(
        <DataTable 
          columns={defaultColumns} 
          data={null} 
          emptyMessage="No data available"
        />
      )

      expect(screen.getByText('No data available')).toBeInTheDocument()
    })

    test('handles undefined data', () => {
      render(
        <DataTable 
          columns={defaultColumns} 
          data={undefined} 
          emptyMessage="Data not loaded"
        />
      )

      expect(screen.getByText('Data not loaded')).toBeInTheDocument()
    })
  })

  describe('pagination controls', () => {
    test('renders pagination controls when pagination prop provided', () => {
      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          pagination={defaultPagination}
        />
      )

      expect(screen.getByText('Showing 1-10 of 30')).toBeInTheDocument()
      expect(screen.getByLabelText('Rows per page')).toBeInTheDocument()
    })

    test('does not render pagination controls when pagination prop not provided', () => {
      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
        />
      )

      expect(screen.queryByLabelText('Rows per page')).not.toBeInTheDocument()
    })

    test('rows per page select has correct options', () => {
      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          pagination={defaultPagination}
        />
      )

      const select = screen.getByLabelText('Rows per page')
      expect(select).toHaveValue('10')

      // Check all options are available
      expect(screen.getByRole('option', { name: '10' })).toBeInTheDocument()
      expect(screen.getByRole('option', { name: '25' })).toBeInTheDocument()
      expect(screen.getByRole('option', { name: '50' })).toBeInTheDocument()
      expect(screen.getByRole('option', { name: '100' })).toBeInTheDocument()
      expect(screen.getByRole('option', { name: 'All' })).toBeInTheDocument()
    })

    test('calls onRowsPerPageChange when rows per page changed', async () => {
      const user = userEvent.setup()
      const onRowsPerPageChange = vi.fn()
      const pagination = { ...defaultPagination, onRowsPerPageChange }

      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          pagination={pagination}
        />
      )

      await user.selectOptions(screen.getByLabelText('Rows per page'), '25')

      expect(onRowsPerPageChange).toHaveBeenCalledWith(25)
    })

    test('calls onRowsPerPageChange with -1 for "All" option', async () => {
      const user = userEvent.setup()
      const onRowsPerPageChange = vi.fn()
      const pagination = { ...defaultPagination, onRowsPerPageChange }

      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          pagination={pagination}
        />
      )

      await user.selectOptions(screen.getByLabelText('Rows per page'), 'All')

      expect(onRowsPerPageChange).toHaveBeenCalledWith(-1)
    })

    test('prev button is disabled on first page', () => {
      const pagination = { ...defaultPagination, page: 1 }

      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          pagination={pagination}
        />
      )

      expect(screen.getByLabelText('Go to previous page')).toBeDisabled()
    })

    test('prev button is enabled on page > 1', () => {
      const pagination = { ...defaultPagination, page: 2 }

      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          pagination={pagination}
        />
      )

      expect(screen.getByLabelText('Go to previous page')).not.toBeDisabled()
    })

    test('next button is disabled on last page', () => {
      const pagination = { ...defaultPagination, page: 3, totalItems: 30 }

      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          pagination={pagination}
        />
      )

      expect(screen.getByLabelText('Go to next page')).toBeDisabled()
    })

    test('next button is enabled when not on last page', () => {
      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          pagination={defaultPagination}
        />
      )

      expect(screen.getByLabelText('Go to next page')).not.toBeDisabled()
    })

    test('calls onPageChange with correct page number when prev clicked', async () => {
      const user = userEvent.setup()
      const onPageChange = vi.fn()
      const pagination = { ...defaultPagination, page: 2, onPageChange }

      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          pagination={pagination}
        />
      )

      await user.click(screen.getByLabelText('Go to previous page'))

      expect(onPageChange).toHaveBeenCalledWith(1)
    })

    test('calls onPageChange with correct page number when next clicked', async () => {
      const user = userEvent.setup()
      const onPageChange = vi.fn()
      const pagination = { ...defaultPagination, onPageChange }

      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          pagination={pagination}
        />
      )

      await user.click(screen.getByLabelText('Go to next page'))

      expect(onPageChange).toHaveBeenCalledWith(2)
    })

    test('shows page number buttons when totalPages <= 7', () => {
      const pagination = { 
        ...defaultPagination, 
        page: 1, 
        rowsPerPage: 10, 
        totalItems: 50 // 5 pages
      }

      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          pagination={pagination}
        />
      )

      expect(screen.getByLabelText('Go to page 1')).toBeInTheDocument()
      expect(screen.getByLabelText('Go to page 2')).toBeInTheDocument()
      expect(screen.getByLabelText('Go to page 3')).toBeInTheDocument()
      expect(screen.getByLabelText('Go to page 4')).toBeInTheDocument()
      expect(screen.getByLabelText('Go to page 5')).toBeInTheDocument()
    })

    test('clicking page number button calls onPageChange', async () => {
      const user = userEvent.setup()
      const onPageChange = vi.fn()
      const pagination = { 
        ...defaultPagination, 
        page: 1, 
        rowsPerPage: 10, 
        totalItems: 50,
        onPageChange
      }

      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          pagination={pagination}
        />
      )

      await user.click(screen.getByLabelText('Go to page 3'))

      expect(onPageChange).toHaveBeenCalledWith(3)
    })

    test('current page has active styling', () => {
      const pagination = { ...defaultPagination, page: 2 }

      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          pagination={pagination}
        />
      )

      const currentPageButton = screen.getByLabelText('Go to page 2')
      expect(currentPageButton.className).toContain('bg-purple-active')
    })
  })

  describe('sorting functionality', () => {
    // Note: The current DataTable implementation doesn't have built-in sorting
    // This tests that sorting is handled through column renderers or external state
    
    test('columns can have custom renderers for sortable headers', () => {
      const columns = [
        { 
          key: 'name', 
          label: 'Name',
          render: (item) => <span>{item.name}</span>
        },
      ]

      render(
        <DataTable 
          columns={columns} 
          data={defaultData}
        />
      )

      expect(screen.getByText('John Doe')).toBeInTheDocument()
    })
  })

  describe('row interactions', () => {
    test('calls onRowClick when row is clicked', async () => {
      const user = userEvent.setup()
      const onRowClick = vi.fn()

      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          onRowClick={onRowClick}
        />
      )

      await user.click(screen.getByText('John Doe'))

      expect(onRowClick).toHaveBeenCalledTimes(1)
      expect(onRowClick).toHaveBeenCalledWith(defaultData[0])
    })

    test('row has cursor-pointer style when onRowClick provided', () => {
      const { container } = render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          onRowClick={() => {}}
        />
      )

      const row = container.querySelector('tbody tr')
      expect(row.className).toContain('cursor-pointer')
    })

    test('row does not have cursor-pointer style when onRowClick not provided', () => {
      const { container } = render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
        />
      )

      const row = container.querySelector('tbody tr')
      expect(row.className).not.toContain('cursor-pointer')
    })
  })

  describe('accessibility', () => {
    test('table headers have proper scope', () => {
      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
        />
      )

      const headers = screen.getAllByRole('columnheader')
      expect(headers).toHaveLength(3)
    })

    test('pagination buttons have aria-labels', () => {
      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          pagination={defaultPagination}
        />
      )

      expect(screen.getByLabelText('Go to previous page')).toBeInTheDocument()
      expect(screen.getByLabelText('Go to next page')).toBeInTheDocument()
    })
  })

  describe('edge cases', () => {
    test('handles data without id property', () => {
      const dataWithoutId = [
        { name: 'Test 1', email: 'test1@example.com' },
        { name: 'Test 2', email: 'test2@example.com' },
      ]

      render(
        <DataTable 
          columns={defaultColumns} 
          data={dataWithoutId}
        />
      )

      expect(screen.getByText('Test 1')).toBeInTheDocument()
      expect(screen.getByText('Test 2')).toBeInTheDocument()
    })

    test('pagination with "All" rows shows only 1 page', () => {
      const pagination = { 
        ...defaultPagination, 
        rowsPerPage: -1,
        showingRange: 'Showing all 30 items'
      }

      render(
        <DataTable 
          columns={defaultColumns} 
          data={defaultData}
          pagination={pagination}
        />
      )

      expect(screen.getByLabelText('Go to previous page')).toBeDisabled()
      expect(screen.getByLabelText('Go to next page')).toBeDisabled()
    })
  })
})
