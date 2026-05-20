import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import RowsPerPageSelect from './RowsPerPageSelect'

describe('RowsPerPageSelect', () => {
  describe('rendering', () => {
    test('renders a select element', () => {
      render(<RowsPerPageSelect value={10} onChange={() => {}} />)

      const select = screen.getByRole('combobox')
      expect(select).toBeInTheDocument()
    })

    test('renders all row count options', () => {
      render(<RowsPerPageSelect value={10} onChange={() => {}} />)

      expect(screen.getByText('Rows: 10')).toBeInTheDocument()
      expect(screen.getByText('Rows: 25')).toBeInTheDocument()
      expect(screen.getByText('Rows: 50')).toBeInTheDocument()
      expect(screen.getByText('Rows: 100')).toBeInTheDocument()
      expect(screen.getByText('Rows: All')).toBeInTheDocument()
    })

    test('selects the matching option for value 10', () => {
      render(<RowsPerPageSelect value={10} onChange={() => {}} />)

      const select = screen.getByRole('combobox')
      expect(select).toHaveValue('10')
    })

    test('selects the matching option for value 25', () => {
      render(<RowsPerPageSelect value={25} onChange={() => {}} />)

      const select = screen.getByRole('combobox')
      expect(select).toHaveValue('25')
    })

    test('selects the matching option for value -1 (All)', () => {
      render(<RowsPerPageSelect value={-1} onChange={() => {}} />)

      const select = screen.getByRole('combobox')
      expect(select).toHaveValue('-1')
    })
  })

  describe('interaction', () => {
    test('calls onChange with numeric value when selection changes', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()

      render(<RowsPerPageSelect value={10} onChange={handleChange} />)

      const select = screen.getByRole('combobox')
      await user.selectOptions(select, '25')

      expect(handleChange).toHaveBeenCalledWith(25)
    })

    test('calls onChange with -1 when All is selected', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()

      render(<RowsPerPageSelect value={10} onChange={handleChange} />)

      const select = screen.getByRole('combobox')
      await user.selectOptions(select, '-1')

      expect(handleChange).toHaveBeenCalledWith(-1)
    })
  })

  describe('accessibility', () => {
    test('has aria-label', () => {
      render(<RowsPerPageSelect value={10} onChange={() => {}} />)

      const select = screen.getByRole('combobox')
      expect(select).toHaveAttribute('aria-label', 'Rows per page')
    })
  })

  describe('styling', () => {
    test('has focus ring styling', () => {
      render(<RowsPerPageSelect value={10} onChange={() => {}} />)

      const select = screen.getByRole('combobox')
      expect(select.className).toContain('focus:ring-purple-active')
    })

    test('has small text size', () => {
      render(<RowsPerPageSelect value={10} onChange={() => {}} />)

      const select = screen.getByRole('combobox')
      expect(select.className).toContain('text-xs')
    })
  })
})
