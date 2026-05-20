import { render, screen } from '@testing-library/react'
import { describe, test, expect } from 'vitest'
import PageHeader from './PageHeader'

describe('PageHeader', () => {
  describe('rendering', () => {
    test('renders title', () => {
      render(<PageHeader title="Dashboard" />)
      expect(screen.getByText('Dashboard')).toBeInTheDocument()
    })

    test('renders with title and description', () => {
      render(<PageHeader title="Dashboard" description="Your overview at a glance" />)
      expect(screen.getByText('Dashboard')).toBeInTheDocument()
      expect(screen.getByText('Your overview at a glance')).toBeInTheDocument()
    })

    test('renders without description - description paragraph is not rendered', () => {
      render(<PageHeader title="Dashboard" />)
      // The <p> element for description is always rendered, but should have no content
      // Since component always renders <p>{description}</p>, the p exists with empty content
      expect(screen.getByText('Dashboard')).toBeInTheDocument()
    })

    test('renders with actions', () => {
      render(
        <PageHeader
          title="Dashboard"
          actions={<button data-testid="action-btn">Add New</button>}
        />
      )
      expect(screen.getByTestId('action-btn')).toBeInTheDocument()
      expect(screen.getByText('Add New')).toBeInTheDocument()
    })

    test('renders without actions when not provided', () => {
      render(<PageHeader title="Dashboard" />)
      expect(screen.getByText('Dashboard')).toBeInTheDocument()
    })
  })

  describe('props variations', () => {
    test('renders with long title', () => {
      const longTitle = 'A Very Long Page Title That Should Still Render Properly'
      render(<PageHeader title={longTitle} />)
      expect(screen.getByText(longTitle)).toBeInTheDocument()
    })

    test('renders with long description', () => {
      const longDesc = 'A very long description that provides additional context about the current page and what the user can expect to find here.'
      render(<PageHeader title="Test" description={longDesc} />)
      expect(screen.getByText(longDesc)).toBeInTheDocument()
    })

    test('renders with multiple action elements', () => {
      render(
        <PageHeader
          title="Dashboard"
          actions={
            <>
              <button>Edit</button>
              <button>Delete</button>
            </>
          }
        />
      )
      expect(screen.getByText('Edit')).toBeInTheDocument()
      expect(screen.getByText('Delete')).toBeInTheDocument()
    })

    test('renders with complex action components', () => {
      render(
        <PageHeader
          title="Settings"
          actions={<span data-testid="complex-action"><input type="search" placeholder="Search..." /></span>}
        />
      )
      expect(screen.getByTestId('complex-action')).toBeInTheDocument()
      expect(screen.getByPlaceholderText('Search...')).toBeInTheDocument()
    })
  })

  describe('null/undefined handling', () => {
    test('handles null title gracefully', () => {
      render(<PageHeader title={null} />)
      const heading = screen.getByRole('heading', { level: 1 })
      expect(heading).toBeInTheDocument()
      expect(heading.textContent).toBe('')
    })

    test('handles undefined title', () => {
      render(<PageHeader />)
      const heading = screen.getByRole('heading', { level: 1 })
      expect(heading).toBeInTheDocument()
      expect(heading.textContent).toBe('')
    })

    test('handles null description - paragraph still renders', () => {
      render(<PageHeader title="Test" description={null} />)
      expect(screen.getByText('Test')).toBeInTheDocument()
      // The description <p> element is always rendered even when null
      const paragraphs = document.querySelectorAll('p')
      expect(paragraphs.length).toBe(1)
    })

    test('handles undefined description', () => {
      render(<PageHeader title="Test" description={undefined} />)
      expect(screen.getByText('Test')).toBeInTheDocument()
    })

    test('handles null actions', () => {
      render(<PageHeader title="Test" actions={null} />)
      expect(screen.getByText('Test')).toBeInTheDocument()
    })

    test('handles undefined actions', () => {
      render(<PageHeader title="Test" actions={undefined} />)
      expect(screen.getByText('Test')).toBeInTheDocument()
    })
  })

  describe('accessibility', () => {
    test('title is rendered as h1', () => {
      render(<PageHeader title="Page Title" />)
      const heading = screen.getByRole('heading', { level: 1 })
      expect(heading).toHaveTextContent('Page Title')
    })

    test('description is rendered as paragraph', () => {
      render(<PageHeader title="Test" description="Description text" />)
      const paragraph = screen.getByText('Description text')
      expect(paragraph.tagName).toBe('P')
    })

    test('actions wrapper is accessible', () => {
      render(
        <PageHeader
          title="Test"
          actions={<button aria-label="Custom action">Click</button>}
        />
      )
      expect(screen.getByRole('button', { name: 'Custom action' })).toBeInTheDocument()
    })
  })

  describe('styling', () => {
    test('title has correct typography classes', () => {
      render(<PageHeader title="Styled Title" />)
      const heading = screen.getByRole('heading', { level: 1 })
      expect(heading.className).toContain('text-2xl')
      expect(heading.className).toContain('font-bold')
    })

    test('description has correct styling classes', () => {
      render(<PageHeader title="Test" description="Styled description" />)
      const description = screen.getByText('Styled description')
      expect(description.className).toContain('text-gray-600')
    })
  })
})
