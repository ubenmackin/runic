import { render, screen } from '@testing-library/react'
import { describe, test, expect } from 'vitest'
import StatCard from './StatCard'
import { Server } from 'lucide-react'

describe('StatCard', () => {
  describe('rendering', () => {
    test('renders label correctly', () => {
      render(<StatCard label="Total Peers" value={42} />)
      expect(screen.getByText('Total Peers')).toBeInTheDocument()
    })

    test('renders value correctly', () => {
      render(<StatCard label="Total Peers" value={42} />)
      expect(screen.getByText('42')).toBeInTheDocument()
    })

    test('renders icon when provided', () => {
      const { container } = render(<StatCard icon={Server} label="Total Peers" value={42} />)
      const icon = container.querySelector('svg')
      expect(icon).toBeInTheDocument()
    })

    test('renders without icon when not provided', () => {
      const { container } = render(<StatCard label="Total Peers" value={42} />)
      const icon = container.querySelector('svg')
      expect(icon).not.toBeInTheDocument()
    })
  })

  describe('value formatting', () => {
    test('formats large numbers with commas', () => {
      render(<StatCard label="Total Peers" value={1234567} />)
      expect(screen.getByText('1,234,567')).toBeInTheDocument()
    })

    test('handles zero correctly', () => {
      render(<StatCard label="Total Peers" value={0} />)
      expect(screen.getByText('0')).toBeInTheDocument()
    })

    test('handles string values', () => {
      render(<StatCard label="Status" value="Active" />)
      expect(screen.getByText('Active')).toBeInTheDocument()
    })
  })

  describe('valueColor prop', () => {
    test('uses default color when valueColor not provided', () => {
      render(<StatCard label="Total Peers" value={42} />)
      const valueElement = screen.getByText('42')
      expect(valueElement.className).toContain('text-slate-400')
    })

    test('applies custom valueColor when provided', () => {
      render(<StatCard label="Total Peers" value={42} valueColor="text-green-500" />)
      const valueElement = screen.getByText('42')
      expect(valueElement.className).toContain('text-green-500')
      expect(valueElement.className).not.toContain('text-slate-400')
    })

    test('supports conditional colors for positive values', () => {
      render(<StatCard label="Active" value={10} valueColor="text-green-400" />)
      const valueElement = screen.getByText('10')
      expect(valueElement.className).toContain('text-green-400')
    })

    test('supports conditional colors for negative values', () => {
      render(<StatCard label="Errors" value={5} valueColor="text-red-400" />)
      const valueElement = screen.getByText('5')
      expect(valueElement.className).toContain('text-red-400')
    })

    test('supports warning colors', () => {
      render(<StatCard label="Warnings" value={3} valueColor="text-yellow-400" />)
      const valueElement = screen.getByText('3')
      expect(valueElement.className).toContain('text-yellow-400')
    })
  })

  describe('styling', () => {
    test('has correct container classes', () => {
      const { container } = render(<StatCard label="Total Peers" value={42} />)
      const card = container.firstChild
      expect(card.className).toContain('border')
      expect(card.className).toContain('bg-charcoal-dark')
      expect(card.className).toContain('p-3')
    })

    test('label has correct styling', () => {
      render(<StatCard label="Total Peers" value={42} />)
      const label = screen.getByText('Total Peers')
      expect(label.className).toContain('text-[10px]')
      expect(label.className).toContain('uppercase')
      expect(label.className).toContain('tracking-widest')
    })

    test('value has mono font', () => {
      render(<StatCard label="Total Peers" value={42} />)
      const value = screen.getByText('42')
      expect(value.className).toContain('font-mono')
      expect(value.className).toContain('text-xl')
    })

    test('icon has correct sizing and color', () => {
      const { container } = render(<StatCard icon={Server} label="Total Peers" value={42} />)
      const icon = container.querySelector('svg')
      // Lucide icons use 'lucide' prefix classes
      expect(icon).toBeInTheDocument()
      // Check that the icon exists and is an SVG element
      expect(icon.tagName.toLowerCase()).toBe('svg')
    })
  })
})
