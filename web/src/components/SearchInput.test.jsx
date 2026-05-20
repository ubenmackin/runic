import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import SearchInput from './SearchInput'

describe('SearchInput', () => {
  describe('rendering', () => {
    test('renders input with default placeholder', () => {
      render(<SearchInput value="" onChange={() => {}} />)

      const input = screen.getByRole('textbox')
      expect(input).toBeInTheDocument()
      expect(input).toHaveAttribute('placeholder', 'Search...')
    })

    test('renders input with custom placeholder', () => {
      render(<SearchInput value="" onChange={() => {}} placeholder="Search policies..." />)

      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('placeholder', 'Search policies...')
    })

    test('renders with the provided value', () => {
      render(<SearchInput value="hello" onChange={() => {}} />)

      const input = screen.getByRole('textbox')
      expect(input).toHaveValue('hello')
    })

    test('renders search icon', () => {
      const { container } = render(<SearchInput value="" onChange={() => {}} />)

      const svg = container.querySelector('svg')
      expect(svg).toBeInTheDocument()
    })

    test('renders clear button when value is present', () => {
      render(<SearchInput value="test" onChange={() => {}} />)

      expect(screen.getByRole('button', { name: /clear search/i })).toBeInTheDocument()
    })

    test('does not render clear button when value is empty', () => {
      render(<SearchInput value="" onChange={() => {}} />)

      expect(screen.queryByRole('button', { name: /clear search/i })).not.toBeInTheDocument()
    })
  })

  describe('accessibility', () => {
    test('input has default aria-label', () => {
      render(<SearchInput value="" onChange={() => {}} />)

      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('aria-label', 'Search')
    })

    test('input has custom aria-label', () => {
      render(<SearchInput value="" onChange={() => {}} ariaLabel="Search policies" />)

      const input = screen.getByRole('textbox')
      expect(input).toHaveAttribute('aria-label', 'Search policies')
    })

    test('clear button has aria-label', () => {
      render(<SearchInput value="test" onChange={() => {}} />)

      const clearButton = screen.getByRole('button', { name: /clear search/i })
      expect(clearButton).toHaveAttribute('aria-label', 'Clear search')
    })
  })

  describe('interaction', () => {
    test('calls onChange when typing', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()

      render(<SearchInput value="" onChange={handleChange} />)

      const input = screen.getByRole('textbox')
      await user.type(input, 'a')

      expect(handleChange).toHaveBeenCalledWith('a')
    })

    test('calls onClear when clear button is clicked', async () => {
      const user = userEvent.setup()
      const handleClear = vi.fn()

      render(<SearchInput value="test" onChange={() => {}} onClear={handleClear} />)

      await user.click(screen.getByRole('button', { name: /clear search/i }))

      expect(handleClear).toHaveBeenCalledTimes(1)
    })
  })

  describe('styling', () => {
    test('input has focus ring styling', () => {
      render(<SearchInput value="" onChange={() => {}} />)

      const input = screen.getByRole('textbox')
      expect(input.className).toContain('focus:ring-2')
      expect(input.className).toContain('focus:ring-purple-active')
    })

    test('container has relative positioning for icon placement', () => {
      const { container } = render(<SearchInput value="" onChange={() => {}} />)

      const wrapper = container.firstChild
      expect(wrapper.className).toContain('relative')
    })
  })

  describe('null/undefined handling', () => {
    test('handles undefined onClear gracefully', () => {
      render(<SearchInput value="test" onChange={() => {}} onClear={undefined} />)

      expect(screen.getByRole('button', { name: /clear search/i })).toBeInTheDocument()
    })

    test('handles empty string value', () => {
      render(<SearchInput value="" onChange={() => {}} />)

      const input = screen.getByRole('textbox')
      expect(input).toHaveValue('')
    })
  })
})
