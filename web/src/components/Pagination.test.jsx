import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import Pagination from './Pagination'

describe('Pagination', () => {
  describe('rendering', () => {
    test('renders page info text', () => {
      render(
        <Pagination
          showingRange="1-10 of 100"
          page={1}
          totalPages={10}
          onPageChange={() => {}}
          totalItems={100}
        />
      )
      expect(screen.getByText('1-10 of 100')).toBeInTheDocument()
    })

    test('renders "Page X of Y" text', () => {
      render(
        <Pagination
          showingRange="1-10 of 100"
          page={3}
          totalPages={10}
          onPageChange={() => {}}
          totalItems={100}
        />
      )
      expect(screen.getByText('Page 3 of 10')).toBeInTheDocument()
    })

    test('renders previous and next buttons', () => {
      render(
        <Pagination
          showingRange="1-10 of 100"
          page={2}
          totalPages={5}
          onPageChange={() => {}}
          totalItems={100}
        />
      )
      expect(screen.getByRole('button', { name: /previous page/i })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /next page/i })).toBeInTheDocument()
    })
  })

  describe('hidden when no items', () => {
    test('returns null when totalItems is 0', () => {
      const { container } = render(
        <Pagination
          showingRange="0 of 0"
          page={1}
          totalPages={1}
          onPageChange={() => {}}
          totalItems={0}
        />
      )
      expect(container.innerHTML).toBe('')
    })

    test('returns null when totalItems is undefined', () => {
      const { container } = render(
        <Pagination
          showingRange="0 of 0"
          page={1}
          totalPages={1}
          onPageChange={() => {}}
          totalItems={undefined}
        />
      )
      expect(container.innerHTML).toBe('')
    })

    test('returns null when totalItems is null', () => {
      const { container } = render(
        <Pagination
          showingRange="0 of 0"
          page={1}
          totalPages={1}
          onPageChange={() => {}}
          totalItems={null}
        />
      )
      expect(container.innerHTML).toBe('')
    })

    test('returns null when totalItems is negative', () => {
      const { container } = render(
        <Pagination
          showingRange="0 of 0"
          page={1}
          totalPages={1}
          onPageChange={() => {}}
          totalItems={-1}
        />
      )
      expect(container.innerHTML).toBe('')
    })
  })

  describe('button states', () => {
    test('previous button is disabled on first page', () => {
      render(
        <Pagination
          showingRange="1-10 of 100"
          page={1}
          totalPages={10}
          onPageChange={() => {}}
          totalItems={100}
        />
      )
      const prevButton = screen.getByRole('button', { name: /previous page/i })
      expect(prevButton).toBeDisabled()
    })

    test('previous button is enabled on non-first page', () => {
      render(
        <Pagination
          showingRange="11-20 of 100"
          page={2}
          totalPages={10}
          onPageChange={() => {}}
          totalItems={100}
        />
      )
      const prevButton = screen.getByRole('button', { name: /previous page/i })
      expect(prevButton).not.toBeDisabled()
    })

    test('next button is disabled on last page', () => {
      render(
        <Pagination
          showingRange="91-100 of 100"
          page={10}
          totalPages={10}
          onPageChange={() => {}}
          totalItems={100}
        />
      )
      const nextButton = screen.getByRole('button', { name: /next page/i })
      expect(nextButton).toBeDisabled()
    })

    test('next button is enabled on non-last page', () => {
      render(
        <Pagination
          showingRange="1-10 of 100"
          page={5}
          totalPages={10}
          onPageChange={() => {}}
          totalItems={100}
        />
      )
      const nextButton = screen.getByRole('button', { name: /next page/i })
      expect(nextButton).not.toBeDisabled()
    })

    test('both buttons enabled on middle page', () => {
      render(
        <Pagination
          showingRange="41-50 of 100"
          page={5}
          totalPages={10}
          onPageChange={() => {}}
          totalItems={100}
        />
      )
      expect(screen.getByRole('button', { name: /previous page/i })).not.toBeDisabled()
      expect(screen.getByRole('button', { name: /next page/i })).not.toBeDisabled()
    })

    test('both buttons disabled when only one page', () => {
      render(
        <Pagination
          showingRange="1-5 of 5"
          page={1}
          totalPages={1}
          onPageChange={() => {}}
          totalItems={5}
        />
      )
      expect(screen.getByRole('button', { name: /previous page/i })).toBeDisabled()
      expect(screen.getByRole('button', { name: /next page/i })).toBeDisabled()
    })
  })

  describe('interaction', () => {
    test('calls onPageChange with decremented page on previous click', async () => {
      const user = userEvent.setup()
      const handlePageChange = vi.fn()

      render(
        <Pagination
          showingRange="11-20 of 100"
          page={2}
          totalPages={10}
          onPageChange={handlePageChange}
          totalItems={100}
        />
      )

      await user.click(screen.getByRole('button', { name: /previous page/i }))
      expect(handlePageChange).toHaveBeenCalledWith(1)
    })

    test('calls onPageChange with incremented page on next click', async () => {
      const user = userEvent.setup()
      const handlePageChange = vi.fn()

      render(
        <Pagination
          showingRange="11-20 of 100"
          page={2}
          totalPages={10}
          onPageChange={handlePageChange}
          totalItems={100}
        />
      )

      await user.click(screen.getByRole('button', { name: /next page/i }))
      expect(handlePageChange).toHaveBeenCalledWith(3)
    })

    test('previous button does not call onPageChange on first page', async () => {
      const user = userEvent.setup()
      const handlePageChange = vi.fn()

      render(
        <Pagination
          showingRange="1-10 of 100"
          page={1}
          totalPages={10}
          onPageChange={handlePageChange}
          totalItems={100}
        />
      )

      const prevButton = screen.getByRole('button', { name: /previous page/i })
      await user.click(prevButton)
      expect(handlePageChange).not.toHaveBeenCalled()
    })

    test('next button does not call onPageChange on last page', async () => {
      const user = userEvent.setup()
      const handlePageChange = vi.fn()

      render(
        <Pagination
          showingRange="91-100 of 100"
          page={10}
          totalPages={10}
          onPageChange={handlePageChange}
          totalItems={100}
        />
      )

      const nextButton = screen.getByRole('button', { name: /next page/i })
      await user.click(nextButton)
      expect(handlePageChange).not.toHaveBeenCalled()
    })
  })

  describe('null/undefined handling', () => {
    test('handles undefined showingRange', () => {
      render(
        <Pagination
          showingRange={undefined}
          page={1}
          totalPages={1}
          onPageChange={() => {}}
          totalItems={5}
        />
      )
      expect(screen.getByText('Page 1 of 1')).toBeInTheDocument()
    })

    test('handles null showingRange', () => {
      render(
        <Pagination
          showingRange={null}
          page={1}
          totalPages={1}
          onPageChange={() => {}}
          totalItems={5}
        />
      )
      expect(screen.getByText('Page 1 of 1')).toBeInTheDocument()
    })

    test('handles undefined onPageChange', () => {
      render(
        <Pagination
          showingRange="1-5 of 5"
          page={1}
          totalPages={1}
          onPageChange={undefined}
          totalItems={5}
        />
      )
      expect(screen.getByText('Page 1 of 1')).toBeInTheDocument()
    })

    test('handles null onPageChange', () => {
      render(
        <Pagination
          showingRange="1-5 of 5"
          page={1}
          totalPages={1}
          onPageChange={null}
          totalItems={5}
        />
      )
      expect(screen.getByText('Page 1 of 1')).toBeInTheDocument()
    })

    test('handles undefined page', () => {
      render(
        <Pagination
          showingRange="1-5 of 5"
          page={undefined}
          totalPages={1}
          onPageChange={() => {}}
          totalItems={5}
        />
      )
      // React renders undefined as empty string in JSX
      expect(screen.getByText(/Page.*of 1/)).toBeInTheDocument()
    })
  })

  describe('accessibility', () => {
    test('previous button has aria-label', () => {
      render(
        <Pagination
          showingRange="1-10 of 100"
          page={2}
          totalPages={5}
          onPageChange={() => {}}
          totalItems={100}
        />
      )
      expect(screen.getByLabelText('Previous page')).toBeInTheDocument()
    })

    test('next button has aria-label', () => {
      render(
        <Pagination
          showingRange="1-10 of 100"
          page={2}
          totalPages={5}
          onPageChange={() => {}}
          totalItems={100}
        />
      )
      expect(screen.getByLabelText('Next page')).toBeInTheDocument()
    })

    test('previous button has title', () => {
      render(
        <Pagination
          showingRange="1-10 of 100"
          page={2}
          totalPages={5}
          onPageChange={() => {}}
          totalItems={100}
        />
      )
      expect(screen.getByTitle('Previous page')).toBeInTheDocument()
    })

    test('next button has title', () => {
      render(
        <Pagination
          showingRange="1-10 of 100"
          page={2}
          totalPages={5}
          onPageChange={() => {}}
          totalItems={100}
        />
      )
      expect(screen.getByTitle('Next page')).toBeInTheDocument()
    })

    test('disabled buttons are still present', () => {
      render(
        <Pagination
          showingRange="1-10 of 100"
          page={1}
          totalPages={10}
          onPageChange={() => {}}
          totalItems={100}
        />
      )
      const prevButton = screen.getByRole('button', { name: /previous page/i })
      expect(prevButton).toBeDisabled()
      expect(prevButton).toHaveAttribute('disabled')
    })
  })
})
