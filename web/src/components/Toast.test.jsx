import { render, screen } from '@testing-library/react'
import { describe, test, expect } from 'vitest'
import Toast from './Toast'

describe('Toast', () => {
  describe('rendering', () => {
    test('renders success toast with message', () => {
      render(<Toast toast={{ type: 'success', message: 'Operation completed' }} />)
      expect(screen.getByText('Operation completed')).toBeInTheDocument()
    })

    test('renders error toast with message', () => {
      render(<Toast toast={{ type: 'error', message: 'Something went wrong' }} />)
      expect(screen.getByText('Something went wrong')).toBeInTheDocument()
    })

    test('renders with index offset', () => {
      const { container } = render(
        <Toast toast={{ type: 'success', message: 'Toast message' }} index={3} />
      )
      const toastEl = container.firstChild
      // With index 3: bottomOffset = 16 + 3 * 56 = 184
      expect(toastEl.style.bottom).toBe('184px')
    })

    test('renders at default bottom offset when index is 0', () => {
      const { container } = render(
        <Toast toast={{ type: 'success', message: 'Toast message' }} index={0} />
      )
      const toastEl = container.firstChild
      // With index 0: bottomOffset = 16 + 0 * 56 = 16
      expect(toastEl.style.bottom).toBe('16px')
    })
  })

  describe('toast types', () => {
    test('renders check icon for success toast', () => {
      render(<Toast toast={{ type: 'success', message: 'Success!' }} />)
      const svg = document.querySelector('svg')
      expect(svg).toBeInTheDocument()
    })

    test('renders alert icon for error toast', () => {
      render(<Toast toast={{ type: 'error', message: 'Error!' }} />)
      const svg = document.querySelector('svg')
      expect(svg).toBeInTheDocument()
    })

    test('defaults to green background for success', () => {
      const { container } = render(<Toast toast={{ type: 'success', message: 'Done' }} />)
      const toastEl = container.firstChild
      expect(toastEl.className).toContain('bg-green-500')
    })

    test('uses red background for error', () => {
      const { container } = render(<Toast toast={{ type: 'error', message: 'Failed' }} />)
      const toastEl = container.firstChild
      expect(toastEl.className).toContain('bg-red-500')
    })

    test('handles unknown toast type', () => {
      const { container } = render(<Toast toast={{ type: 'info', message: 'Info' }} />)
      const toastEl = container.firstChild
      // Unknown type defaults to green (isError is false)
      expect(toastEl.className).toContain('bg-green-500')
    })
  })

  describe('null/undefined handling', () => {
    test('returns null when toast is null', () => {
      const { container } = render(<Toast toast={null} />)
      expect(container.innerHTML).toBe('')
    })

    test('returns null when toast is undefined', () => {
      const { container } = render(<Toast toast={undefined} />)
      expect(container.innerHTML).toBe('')
    })

    test('handles toast without message', () => {
      render(<Toast toast={{ type: 'success' }} />)
      const span = document.querySelector('span')
      expect(span.textContent).toBe('')
    })

    test('handles toast without type', () => {
      const { container } = render(<Toast toast={{ message: 'Just a message' }} />)
      const toastEl = container.firstChild
      expect(toastEl.className).toContain('bg-green-500')
    })

    test('handles undefined index', () => {
      render(<Toast toast={{ type: 'success', message: 'Test' }} />)
      expect(screen.getByText('Test')).toBeInTheDocument()
    })
  })

  describe('accessibility', () => {
    test('has role="alert"', () => {
      render(<Toast toast={{ type: 'success', message: 'Accessible toast' }} />)
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })

    test('has aria-live="polite"', () => {
      render(<Toast toast={{ type: 'success', message: 'Live region' }} />)
      const alert = screen.getByRole('alert')
      expect(alert).toHaveAttribute('aria-live', 'polite')
    })
  })

  describe('styling', () => {
    test('is positioned fixed', () => {
      const { container } = render(<Toast toast={{ type: 'success', message: 'Toast' }} />)
      const toastEl = container.firstChild
      expect(toastEl.className).toContain('fixed')
    })

    test('is positioned on right side', () => {
      const { container } = render(<Toast toast={{ type: 'success', message: 'Toast' }} />)
      const toastEl = container.firstChild
      expect(toastEl.className).toContain('right-4')
    })

    test('has high z-index', () => {
      const { container } = render(<Toast toast={{ type: 'success', message: 'Toast' }} />)
      const toastEl = container.firstChild
      expect(toastEl.className).toContain('z-50')
    })

    test('has flex layout', () => {
      const { container } = render(<Toast toast={{ type: 'success', message: 'Toast' }} />)
      const toastEl = container.firstChild
      expect(toastEl.className).toContain('flex')
      expect(toastEl.className).toContain('items-center')
      expect(toastEl.className).toContain('gap-2')
    })

    test('has white text color', () => {
      const { container } = render(<Toast toast={{ type: 'success', message: 'Toast' }} />)
      const toastEl = container.firstChild
      expect(toastEl.className).toContain('text-white')
    })
  })
})
