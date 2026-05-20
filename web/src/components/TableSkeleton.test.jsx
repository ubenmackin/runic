import { render } from '@testing-library/react'
import { describe, test, expect } from 'vitest'
import TableSkeleton from './TableSkeleton'

describe('TableSkeleton', () => {
  describe('rendering', () => {
    test('renders without crashing', () => {
      const { container } = render(<TableSkeleton />)
      // The wrapper div has role="status"
      const wrapper = container.firstChild
      expect(wrapper).toBeInTheDocument()
      expect(wrapper.getAttribute('role')).toBe('status')
    })

    test('renders with default rows (5) and columns (4)', () => {
      const { container } = render(<TableSkeleton />)
      const wrapper = container.firstChild
      // Should have 1 header row + 5 body rows = 6 tr elements
      const rows = wrapper.querySelectorAll('tr')
      expect(rows.length).toBe(6) // 1 header + 5 body
      // Each row should have 4 cells (columns)
      rows.forEach(row => {
        expect(row.children.length).toBe(4)
      })
    })

    test('renders with custom row count', () => {
      const { container } = render(<TableSkeleton rows={3} />)
      const wrapper = container.firstChild
      const rows = wrapper.querySelectorAll('tbody tr')
      expect(rows.length).toBe(3)
    })

    test('renders with custom column count', () => {
      const { container } = render(<TableSkeleton columns={6} />)
      const wrapper = container.firstChild
      const headerCells = wrapper.querySelectorAll('thead th')
      expect(headerCells.length).toBe(6)
    })

    test('renders with custom rows and columns', () => {
      const { container } = render(<TableSkeleton rows={10} columns={8} />)
      const wrapper = container.firstChild
      const headerCells = wrapper.querySelectorAll('thead th')
      expect(headerCells.length).toBe(8)
      const bodyRows = wrapper.querySelectorAll('tbody tr')
      expect(bodyRows.length).toBe(10)
    })
  })

  describe('props variations', () => {
    test('renders with 0 rows', () => {
      const { container } = render(<TableSkeleton rows={0} />)
      const wrapper = container.firstChild
      const bodyRows = wrapper.querySelectorAll('tbody tr')
      expect(bodyRows.length).toBe(0)
    })

    test('renders with 0 columns', () => {
      const { container } = render(<TableSkeleton columns={0} />)
      const wrapper = container.firstChild
      const headerCells = wrapper.querySelectorAll('thead th')
      expect(headerCells.length).toBe(0)
      const bodyRows = wrapper.querySelectorAll('tbody tr')
      bodyRows.forEach(row => {
        expect(row.children.length).toBe(0)
      })
    })

    test('renders with 1 row and 1 column', () => {
      const { container } = render(<TableSkeleton rows={1} columns={1} />)
      const wrapper = container.firstChild
      const headerCells = wrapper.querySelectorAll('thead th')
      expect(headerCells.length).toBe(1)
      const bodyRows = wrapper.querySelectorAll('tbody tr')
      expect(bodyRows.length).toBe(1)
    })

    test('renders table structure correctly', () => {
      const { container } = render(<TableSkeleton />)
      const wrapper = container.firstChild
      const table = wrapper.querySelector('table')
      expect(table).toBeInTheDocument()
      expect(table.querySelector('thead')).toBeInTheDocument()
      expect(table.querySelector('tbody')).toBeInTheDocument()
    })
  })

  describe('null/undefined handling', () => {
    test('handles undefined rows - uses default', () => {
      const { container } = render(<TableSkeleton rows={undefined} />)
      const wrapper = container.firstChild
      const bodyRows = wrapper.querySelectorAll('tbody tr')
      expect(bodyRows.length).toBe(5)
    })

    test('handles undefined columns - uses default', () => {
      const { container } = render(<TableSkeleton columns={undefined} />)
      const wrapper = container.firstChild
      const headerCells = wrapper.querySelectorAll('thead th')
      expect(headerCells.length).toBe(4)
    })

    test('handles null rows - generates empty array', () => {
      const { container } = render(<TableSkeleton rows={null} />)
      const wrapper = container.firstChild
      const bodyRows = wrapper.querySelectorAll('tbody tr')
      // Array.from({ length: null }) creates an empty array
      expect(bodyRows.length).toBe(0)
    })
  })

  describe('accessibility', () => {
    test('wrapper div has role="status"', () => {
      const { container } = render(<TableSkeleton />)
      const wrapper = container.firstChild
      expect(wrapper.getAttribute('role')).toBe('status')
    })

    test('has aria-label "Loading table data"', () => {
      const { container } = render(<TableSkeleton />)
      const wrapper = container.firstChild
      expect(wrapper.getAttribute('aria-label')).toBe('Loading table data')
    })
  })

  describe('styling', () => {
    test('has table container styling', () => {
      const { container } = render(<TableSkeleton />)
      const wrapper = container.firstChild
      expect(wrapper.className).toContain('bg-white')
      expect(wrapper.className).toContain('overflow-hidden')
    })

    test('header has correct background', () => {
      const { container } = render(<TableSkeleton />)
      const wrapper = container.firstChild
      const thead = wrapper.querySelector('thead')
      expect(thead.className).toContain('bg-gray-50')
    })

    test('body rows have dividers', () => {
      const { container } = render(<TableSkeleton />)
      const wrapper = container.firstChild
      const tbody = wrapper.querySelector('tbody')
      expect(tbody.className).toContain('divide-y')
    })
  })
})
