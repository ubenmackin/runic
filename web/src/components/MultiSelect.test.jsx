import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import MultiSelect from './MultiSelect'

// Mock scrollIntoView on all elements
Element.prototype.scrollIntoView = vi.fn()

// Mock useDropdownPosition to return stable values
vi.mock('../hooks/useDropdownPosition', () => ({
  useDropdownPosition: () => ({ top: 100, left: 0, width: 300, positionAbove: false }),
}))

const defaultOptions = [
  { value: '1', label: 'Option One' },
  { value: '2', label: 'Option Two' },
  { value: '3', label: 'Option Three' },
]

describe('MultiSelect', () => {
  let user

  beforeEach(() => {
    user = userEvent.setup()
  })

  afterEach(() => {
    // Let React handle cleanup via unmount
  })

  describe('rendering', () => {
    test('renders with placeholder when no values selected', () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={[]}
          onChange={() => {}}
          placeholder="Pick items..."
        />
      )

      expect(screen.getByText('Pick items...')).toBeInTheDocument()
    })

    test('renders comma-separated labels when values selected (default mode)', () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={['1', '3']}
          onChange={() => {}}
        />
      )

      expect(screen.getByText('Option One, Option Three')).toBeInTheDocument()
    })

    test('renders count badge when showCountBadge is true', () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={['1', '2']}
          onChange={() => {}}
          showCountBadge={true}
        />
      )

      expect(screen.getByText('2 selected')).toBeInTheDocument()
    })

    test('truncates long label text', () => {
      const longOptions = [
        { value: '1', label: 'A very long option label that exceeds thirty characters' },
        { value: '2', label: 'Short' },
      ]

      render(
        <MultiSelect
          options={longOptions}
          values={['1', '2']}
          onChange={() => {}}
        />
      )

      expect(screen.getByText(/\.\.\.$/)).toBeInTheDocument()
    })

    test('renders button with aria-haspopup and aria-expanded', () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={[]}
          onChange={() => {}}
        />
      )

      const button = screen.getByRole('button')
      expect(button).toHaveAttribute('aria-haspopup', 'listbox')
      expect(button).toHaveAttribute('aria-expanded', 'false')
    })

    test('applies disabled styles when disabled prop is true', () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={[]}
          onChange={() => {}}
          disabled={true}
        />
      )

      const button = screen.getByRole('button')
      expect(button).toBeDisabled()
    })
  })

  describe('dropdown open/close', () => {
    test('opens dropdown when button is clicked', async () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={[]}
          onChange={() => {}}
        />
      )

      await user.click(screen.getByRole('button'))

      // Dropdown should be in document.body via portal
      expect(screen.getByRole('listbox')).toBeInTheDocument()
    })

    test('closes dropdown when clicking outside', async () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={[]}
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
        <MultiSelect
          options={defaultOptions}
          values={[]}
          onChange={() => {}}
          disabled={true}
        />
      )

      await user.click(screen.getByRole('button'))
      expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
    })
  })

  describe('option selection', () => {
    test('calls onChange with selected value when option is clicked', async () => {
      const handleChange = vi.fn()

      render(
        <MultiSelect
          options={defaultOptions}
          values={[]}
          onChange={handleChange}
        />
      )

      await user.click(screen.getByRole('button'))
      await user.click(screen.getByText('Option One'))

      expect(handleChange).toHaveBeenCalledWith(['1'])
    })

    test('calls onChange with deselected value when selected option is clicked', async () => {
      const handleChange = vi.fn()

      render(
        <MultiSelect
          options={defaultOptions}
          values={['1', '2']}
          onChange={handleChange}
        />
      )

      await user.click(screen.getByRole('button'))
      await user.click(screen.getByText('Option One'))

      expect(handleChange).toHaveBeenCalledWith(['2'])
    })

    test('renders checkbox with check icon for selected options', () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={['1']}
          onChange={() => {}}
        />
      )

      // The button shows the selected label
      expect(screen.getByText('Option One')).toBeInTheDocument()
    })
  })

  describe('search filtering', () => {
    test('filters options based on search input', async () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={[]}
          onChange={() => {}}
        />
      )

      await user.click(screen.getByRole('button'))

      const searchInput = screen.getByLabelText('Search options')
      await user.type(searchInput, 'Two')

      expect(screen.getByText('Option Two')).toBeInTheDocument()
      expect(screen.queryByText('Option One')).not.toBeInTheDocument()
      expect(screen.queryByText('Option Three')).not.toBeInTheDocument()
    })

    test('shows "No options found" when search yields no results', async () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={[]}
          onChange={() => {}}
        />
      )

      await user.click(screen.getByRole('button'))

      const searchInput = screen.getByLabelText('Search options')
      await user.type(searchInput, 'xyz')

      expect(screen.getByText('No options found')).toBeInTheDocument()
    })
  })

  describe('select all / clear all', () => {
    test('Select All selects all filtered options', async () => {
      const handleChange = vi.fn()

      render(
        <MultiSelect
          options={defaultOptions}
          values={[]}
          onChange={handleChange}
        />
      )

      await user.click(screen.getByRole('button'))
      await user.click(screen.getByText('Select All'))

      expect(handleChange).toHaveBeenCalledWith(['1', '2', '3'])
    })

    test('Clear All deselects all filtered options', async () => {
      const handleChange = vi.fn()

      render(
        <MultiSelect
          options={defaultOptions}
          values={['1', '2', '3']}
          onChange={handleChange}
        />
      )

      await user.click(screen.getByRole('button'))
      await user.click(screen.getByText('Clear All'))

      expect(handleChange).toHaveBeenCalledWith([])
    })

    test('Clear All button is disabled when no values are selected', async () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={[]}
          onChange={() => {}}
        />
      )

      await user.click(screen.getByRole('button'))

      const clearButton = screen.getByText('Clear All').closest('button')
      expect(clearButton).toBeDisabled()
    })
  })

  describe('keyboard navigation', () => {
    test('opens dropdown with ArrowDown key', async () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={[]}
          onChange={() => {}}
        />
      )

      const button = screen.getByRole('button')
      button.focus()
      await user.keyboard('{ArrowDown}')

      expect(screen.getByRole('listbox')).toBeInTheDocument()
    })

    test('opens dropdown with Enter key', async () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={[]}
          onChange={() => {}}
        />
      )

      const button = screen.getByRole('button')
      button.focus()
      await user.keyboard('{Enter}')

      expect(screen.getByRole('listbox')).toBeInTheDocument()
    })

    test('closes dropdown with Escape key', async () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={[]}
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

  describe('count badge display', () => {
    test('shows count badge with number when showCountBadge is true and items selected', () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={['1', '2']}
          onChange={() => {}}
          showCountBadge={true}
        />
      )

      expect(screen.getByText('2')).toBeInTheDocument()
    })

    test('does not show count badge when showCountBadge is false', () => {
      render(
        <MultiSelect
          options={defaultOptions}
          values={['1', '2']}
          onChange={() => {}}
          showCountBadge={false}
        />
      )

      expect(screen.getByText('Option One, Option Two')).toBeInTheDocument()
    })
  })
})
