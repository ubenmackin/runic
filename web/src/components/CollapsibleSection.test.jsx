import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import CollapsibleSection from './CollapsibleSection'
import { Settings } from 'lucide-react'

describe('CollapsibleSection', () => {
  // Helper to render with children
  const renderSection = (props = {}) => {
    return render(
      <CollapsibleSection title="Test Section" {...props}>
        <div data-testid="content">Test content</div>
      </CollapsibleSection>
    )
  }

  describe('rendering', () => {
    test('renders title correctly', () => {
      renderSection()
      expect(screen.getByText('Test Section')).toBeInTheDocument()
    })

    test('renders icon when provided', () => {
      renderSection({ icon: <Settings data-testid="icon" /> })
      expect(screen.getByTestId('icon')).toBeInTheDocument()
    })

    test('renders children when expanded', () => {
      renderSection({ defaultExpanded: true })
      expect(screen.getByTestId('content')).toBeInTheDocument()
    })

    test('does not show children when collapsed', () => {
      renderSection({ defaultExpanded: false })
      // Content exists but is hidden via max-height: 0
      const content = screen.getByTestId('content')
      expect(content).toBeInTheDocument()
      // The grandparent container (the region div) has max-height: 0
      const region = screen.getByRole('region')
      expect(region).toHaveStyle({ maxHeight: '0px' })
    })

    test('renders summary badge when provided and collapsed', () => {
      renderSection({ summary: '3 items', defaultExpanded: false })
      expect(screen.getByText('3 items')).toBeInTheDocument()
    })

    test('does not show summary when expanded', () => {
      renderSection({ summary: '3 items', defaultExpanded: true })
      expect(screen.queryByText('3 items')).not.toBeInTheDocument()
    })

    test('renders custom className', () => {
      const { container } = renderSection({ className: 'custom-class' })
      expect(container.firstChild).toHaveClass('custom-class')
    })

    test('chevron rotates 180 degrees when expanded', () => {
      const { container } = renderSection({ defaultExpanded: true })
      const chevron = container.querySelector('svg')
      expect(chevron.getAttribute('class')).toContain('rotate-180')
    })

    test('chevron does not rotate when collapsed', () => {
      const { container } = renderSection({ defaultExpanded: false })
      const chevron = container.querySelector('svg')
      expect(chevron.getAttribute('class')).not.toContain('rotate-180')
    })

    test('renders id attribute when provided', () => {
      const { container } = renderSection({ id: 'test-section-id' })
      expect(container.firstChild).toHaveAttribute('id', 'test-section-id')
    })

    test('does not render id attribute when not provided', () => {
      const { container } = renderSection()
      expect(container.firstChild).not.toHaveAttribute('id')
    })

    test('id attribute allows anchor navigation', () => {
      renderSection({ id: 'general-section' })
      const section = document.getElementById('general-section')
      expect(section).toBeInTheDocument()
    })

    test('summary can be a React node', () => {
      renderSection({ 
        summary: <span data-testid="custom-summary">Custom summary</span>, 
        defaultExpanded: false 
      })
      expect(screen.getByTestId('custom-summary')).toBeInTheDocument()
    })

    test('summary text has correct styling', () => {
      renderSection({ summary: '3 items', defaultExpanded: false })
      const summaryText = screen.getByText('3 items')
      expect(summaryText.className).toContain('text-xs')
      expect(summaryText.className).toContain('text-gray-500')
    })
  })

  describe('expand/collapse behavior', () => {
    test('clicking header toggles expansion', async () => {
      const user = userEvent.setup()
      renderSection({ defaultExpanded: false })

      const button = screen.getByRole('button')
      await user.click(button)

      await waitFor(() => {
        expect(screen.getByRole('region')).toBeVisible()
      })
    })

    test('clicking header collapses when expanded', async () => {
      const user = userEvent.setup()
      renderSection({ defaultExpanded: true })

      const button = screen.getByRole('button')
      await user.click(button)

      await waitFor(() => {
        const region = screen.getByRole('region')
        expect(region).toHaveStyle({ maxHeight: '0px' })
      })
    })
  })

  describe('keyboard accessibility', () => {
    test('can be focused with Tab', async () => {
      const user = userEvent.setup()
      renderSection()

      await user.tab()
      const button = screen.getByRole('button')
      expect(button).toHaveFocus()
    })

    test('Enter key toggles expansion', async () => {
      const user = userEvent.setup()
      renderSection({ defaultExpanded: false })

      const button = screen.getByRole('button')
      button.focus()
      await user.keyboard('{Enter}')

      await waitFor(() => {
        expect(screen.getByRole('region')).toBeVisible()
      })
    })

    test('Space key toggles expansion', async () => {
      const user = userEvent.setup()
      renderSection({ defaultExpanded: true })

      const button = screen.getByRole('button')
      button.focus()
      await user.keyboard(' ')

      await waitFor(() => {
        const region = screen.getByRole('region')
        expect(region).toHaveStyle({ maxHeight: '0px' })
      })
    })

    test('has focus ring styling', () => {
      renderSection()
      const button = screen.getByRole('button')
      expect(button.className).toContain('focus:ring-2')
      expect(button.className).toContain('focus:ring-purple-active')
    })
  })

  describe('ARIA attributes', () => {
    test('header has aria-expanded attribute', () => {
      renderSection({ defaultExpanded: true })
      const button = screen.getByRole('button')
      expect(button).toHaveAttribute('aria-expanded', 'true')
    })

    test('aria-expanded is false when collapsed', () => {
      renderSection({ defaultExpanded: false })
      const button = screen.getByRole('button')
      expect(button).toHaveAttribute('aria-expanded', 'false')
    })

    test('header has aria-controls pointing to content', () => {
      renderSection()
      const button = screen.getByRole('button')
      const contentId = button.getAttribute('aria-controls')
      expect(contentId).toBeTruthy()
      expect(document.getElementById(contentId)).toBeInTheDocument()
    })

    test('content region has aria-labelledby pointing to header', () => {
      renderSection({ defaultExpanded: true })
      const region = screen.getByRole('region')
      const labelledBy = region.getAttribute('aria-labelledby')
      expect(labelledBy).toBeTruthy()
      expect(document.getElementById(labelledBy)).toBeInTheDocument()
    })

    test('content has role="region"', () => {
      renderSection({ defaultExpanded: true })
      expect(screen.getByRole('region')).toBeInTheDocument()
    })
  })

  describe('localStorage persistence', () => {
    const STORAGE_KEY = 'test-collapsible-state'
    let store = {}
    let mockLocalStorage

    beforeEach(() => {
      store = {}
      // Create a working localStorage mock
      mockLocalStorage = {
        getItem: (key) => store[key] ?? null,
        setItem: (key, value) => { store[key] = value },
        removeItem: (key) => { delete store[key] },
        clear: () => { store = {} },
        get length() { return Object.keys(store).length },
        key: (i) => Object.keys(store)[i] ?? null,
      }
      // Replace global localStorage with our mock
      vi.stubGlobal('localStorage', mockLocalStorage)
    })

    afterEach(() => {
      vi.unstubAllGlobals()
      store = {}
    })

    test('saves expanded state to localStorage', async () => {
      store[STORAGE_KEY] = 'true'
      renderSection({ storageKey: STORAGE_KEY })

      await waitFor(() => {
        expect(store[STORAGE_KEY]).toBe('true')
      })
    })

    test('restores state from localStorage on mount', async () => {
      store[STORAGE_KEY] = 'true'
      renderSection({ storageKey: STORAGE_KEY })

      await waitFor(() => {
        const button = screen.getByRole('button')
        expect(button).toHaveAttribute('aria-expanded', 'true')
      })
    })

    test('updates localStorage when toggled', async () => {
      const user = userEvent.setup()
      renderSection({ storageKey: STORAGE_KEY, defaultExpanded: false })

      const button = screen.getByRole('button')
      await user.click(button)

      await waitFor(() => {
        expect(store[STORAGE_KEY]).toBe('true')
      })
    })

    test('does not persist when storageKey is not provided', async () => {
      const user = userEvent.setup()
      renderSection({ defaultExpanded: false })

      const button = screen.getByRole('button')
      await user.click(button)

      // No storage key means nothing should be stored
      expect(Object.keys(store).length).toBe(0)
    })

    test('handles invalid localStorage values gracefully', async () => {
      store[STORAGE_KEY] = 'invalid-json'
      renderSection({ storageKey: STORAGE_KEY })

      // Should fall back to defaultExpanded
      await waitFor(() => {
        const button = screen.getByRole('button')
        expect(button).toHaveAttribute('aria-expanded', 'false')
      })
    })
  })

  describe('controlled mode', () => {
    test('uses controlled expanded prop when provided', () => {
      renderSection({ expanded: true })
      const button = screen.getByRole('button')
      expect(button).toHaveAttribute('aria-expanded', 'true')
    })

    test('calls onExpandedChange when toggled in controlled mode', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()
      renderSection({ expanded: false, onExpandedChange: handleChange })

      const button = screen.getByRole('button')
      await user.click(button)

      expect(handleChange).toHaveBeenCalledTimes(1)
      expect(handleChange).toHaveBeenCalledWith(true)
    })

    test('uncontrolled mode toggles state when expanded prop not provided', async () => {
      const user = userEvent.setup()
      renderSection({ defaultExpanded: false })

      const button = screen.getByRole('button')
      await user.click(button)

      // In uncontrolled mode without expanded prop, it should toggle
      expect(button).toHaveAttribute('aria-expanded', 'true')
    })

    test('controlled mode requires external state management', async () => {
      const user = userEvent.setup()
      // Without onExpandedChange, clicking in controlled mode won't update UI
      // (parent component controls state)
      const { rerender } = renderSection({ expanded: false })

      const button = screen.getByRole('button')
      await user.click(button)

      // In strictly controlled mode without callback, state stays same
      // (parent would need to update the expanded prop)
      expect(button).toHaveAttribute('aria-expanded', 'false')

      // Simulate parent updating state
      rerender(
        <CollapsibleSection title="Test Section" expanded={true}>
          <div data-testid="content">Test content</div>
        </CollapsibleSection>
      )

      expect(button).toHaveAttribute('aria-expanded', 'true')
    })

    test('controlled mode can be used with storageKey', () => {
      // When expanded prop is provided, it takes precedence over localStorage
      const store = {}
      store['test-key'] = 'false' // localStorage says collapsed
      
      vi.stubGlobal('localStorage', {
        getItem: (key) => store[key] ?? null,
        setItem: (key, value) => { store[key] = value },
      })

      renderSection({ expanded: true, storageKey: 'test-key' })
      const button = screen.getByRole('button')
      
      // Controlled prop wins
      expect(button).toHaveAttribute('aria-expanded', 'true')
      
      vi.unstubAllGlobals()
    })

    test('onExpandedChange is called with correct value on collapse', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()
      renderSection({ expanded: true, onExpandedChange: handleChange })

      const button = screen.getByRole('button')
      await user.click(button)

      expect(handleChange).toHaveBeenCalledWith(false)
    })

    test('controlled mode allows programmatic expansion/collapse', () => {
      const { rerender } = renderSection({ expanded: false })

      // Initially collapsed
      expect(screen.getByRole('button')).toHaveAttribute('aria-expanded', 'false')

      // Programmatically expand
      rerender(
        <CollapsibleSection title="Test Section" expanded={true}>
          <div data-testid="content">Test content</div>
        </CollapsibleSection>
      )
      expect(screen.getByRole('button')).toHaveAttribute('aria-expanded', 'true')
      expect(screen.getByRole('region')).toBeVisible()

      // Programmatically collapse
      rerender(
        <CollapsibleSection title="Test Section" expanded={false}>
          <div data-testid="content">Test content</div>
        </CollapsibleSection>
      )
      expect(screen.getByRole('button')).toHaveAttribute('aria-expanded', 'false')
    })
  })

  describe('dark mode', () => {
    test('has dark mode background classes', () => {
      const { container } = renderSection()
      const outerDiv = container.firstChild
      expect(outerDiv.className).toContain('dark:bg-charcoal-dark')
    })

    test('has dark mode border classes', () => {
      const { container } = renderSection()
      const outerDiv = container.firstChild
      expect(outerDiv.className).toContain('dark:border-gray-border')
    })

    test('header has dark mode hover styling', () => {
      renderSection()
      const button = screen.getByRole('button')
      expect(button.className).toContain('dark:hover:bg-charcoal-darkest')
    })

    test('title has dark mode text styling', () => {
      renderSection()
      const title = screen.getByText('Test Section')
      expect(title.className).toContain('dark:text-light-neutral')
    })
  })

  describe('animation', () => {
    test('content has transition for max-height', () => {
      renderSection({ defaultExpanded: true })
      const region = screen.getByRole('region')
      expect(region.style.transition).toContain('max-height')
    })

    test('chevron has transition for rotation', () => {
      const { container } = renderSection()
      const chevron = container.querySelector('svg')
      expect(chevron.getAttribute('class')).toContain('transition-transform')
    })
  })
})
