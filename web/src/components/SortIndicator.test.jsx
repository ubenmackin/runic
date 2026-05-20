import { render } from '@testing-library/react'
import { describe, test, expect } from 'vitest'
import SortIndicator from './SortIndicator'

describe('SortIndicator', () => {
  function getIcon(container) {
    return container.querySelector('svg')
  }

  describe('rendering', () => {
    test('renders unsorted icon when column is not the sort key', () => {
      const { container } = render(
        <SortIndicator columnKey="name" sortConfig={{ key: 'email', direction: 'asc' }} />
      )
      expect(getIcon(container)).toBeInTheDocument()
    })

    test('renders ascending icon when column matches and direction is asc', () => {
      const { container } = render(
        <SortIndicator columnKey="name" sortConfig={{ key: 'name', direction: 'asc' }} />
      )
      expect(getIcon(container)).toBeInTheDocument()
    })

    test('renders descending icon when column matches and direction is desc', () => {
      const { container } = render(
        <SortIndicator columnKey="name" sortConfig={{ key: 'name', direction: 'desc' }} />
      )
      expect(getIcon(container)).toBeInTheDocument()
    })
  })

  describe('sort states', () => {
    test('unsorted column renders unsorted state', () => {
      const { container } = render(
        <SortIndicator columnKey="age" sortConfig={{ key: 'name', direction: 'asc' }} />
      )
      expect(getIcon(container)).toBeInTheDocument()
    })

    test('ascending sort renders', () => {
      const { container } = render(
        <SortIndicator columnKey="name" sortConfig={{ key: 'name', direction: 'asc' }} />
      )
      expect(getIcon(container)).toBeInTheDocument()
    })

    test('descending sort renders', () => {
      const { container } = render(
        <SortIndicator columnKey="name" sortConfig={{ key: 'name', direction: 'desc' }} />
      )
      expect(getIcon(container)).toBeInTheDocument()
    })

    test('switches between sort states', () => {
      const { container, rerender } = render(
        <SortIndicator columnKey="name" sortConfig={{ key: 'email', direction: 'asc' }} />
      )

      expect(getIcon(container)).toBeInTheDocument()

      // Now sort by name ascending
      rerender(
        <SortIndicator columnKey="name" sortConfig={{ key: 'name', direction: 'asc' }} />
      )

      expect(getIcon(container)).toBeInTheDocument()

      // Now sort by name descending
      rerender(
        <SortIndicator columnKey="name" sortConfig={{ key: 'name', direction: 'desc' }} />
      )

      expect(getIcon(container)).toBeInTheDocument()
    })
  })

  describe('null/undefined handling', () => {
    test('handles undefined columnKey', () => {
      const { container } = render(
        <SortIndicator columnKey={undefined} sortConfig={{ key: 'name', direction: 'asc' }} />
      )
      expect(getIcon(container)).toBeInTheDocument()
    })

    test('handles null columnKey', () => {
      const { container } = render(
        <SortIndicator columnKey={null} sortConfig={{ key: 'name', direction: 'asc' }} />
      )
      expect(getIcon(container)).toBeInTheDocument()
    })

    test('handles sortConfig with missing direction', () => {
      const { container } = render(
        <SortIndicator columnKey="name" sortConfig={{ key: 'name' }} />
      )
      expect(getIcon(container)).toBeInTheDocument()
    })

    test('handles sortConfig with empty key', () => {
      const { container } = render(
        <SortIndicator columnKey="name" sortConfig={{ key: '', direction: 'asc' }} />
      )
      expect(getIcon(container)).toBeInTheDocument()
    })
  })

  describe('styling', () => {
    function getIconClasses(container) {
      const icon = getIcon(container)
      return icon ? (icon.getAttribute('class') || '') : ''
    }

    test('unsorted icon has gray color', () => {
      const { container } = render(
        <SortIndicator columnKey="age" sortConfig={{ key: 'name', direction: 'asc' }} />
      )
      expect(getIconClasses(container)).toContain('text-gray-400')
    })

    test('ascending icon has runic color', () => {
      const { container } = render(
        <SortIndicator columnKey="name" sortConfig={{ key: 'name', direction: 'asc' }} />
      )
      expect(getIconClasses(container)).toContain('text-runic-500')
    })

    test('descending icon has runic color', () => {
      const { container } = render(
        <SortIndicator columnKey="name" sortConfig={{ key: 'name', direction: 'desc' }} />
      )
      expect(getIconClasses(container)).toContain('text-runic-500')
    })

    test('icon has left margin', () => {
      const { container } = render(
        <SortIndicator columnKey="name" sortConfig={{ key: 'name', direction: 'asc' }} />
      )
      expect(getIconClasses(container)).toContain('ml-1')
    })

    test('icon has consistent size', () => {
      const { container } = render(
        <SortIndicator columnKey="name" sortConfig={{ key: 'name', direction: 'asc' }} />
      )
      expect(getIconClasses(container)).toContain('w-4')
      expect(getIconClasses(container)).toContain('h-4')
    })
  })
})
