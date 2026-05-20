import { render, screen } from '@testing-library/react'
import { describe, test, expect } from 'vitest'
import TopBlockedSources from './TopBlockedSources'

const sampleSources = [
  { src_ip: '192.168.1.100', count: 150 },
  { src_ip: '10.0.0.50', count: 85 },
  { src_ip: '172.16.0.1', count: 42 },
]

describe('TopBlockedSources', () => {
  describe('rendering', () => {
    test('renders header with title', () => {
      render(<TopBlockedSources sources={[]} />)

      expect(screen.getByText('Top Blocked Sources')).toBeInTheDocument()
      expect(screen.getByText('(24h)')).toBeInTheDocument()
    })

    test('renders empty state when sources array is empty', () => {
      render(<TopBlockedSources sources={[]} />)

      expect(
        screen.getByText('No blocked sources in last 24h')
      ).toBeInTheDocument()
    })

    test('renders source items with IP addresses', () => {
      render(<TopBlockedSources sources={sampleSources} />)

      expect(screen.getByText('192.168.1.100')).toBeInTheDocument()
      expect(screen.getByText('10.0.0.50')).toBeInTheDocument()
      expect(screen.getByText('172.16.0.1')).toBeInTheDocument()
    })

    test('renders count badges for each source', () => {
      render(<TopBlockedSources sources={sampleSources} />)

      expect(screen.getByText('150 blocks')).toBeInTheDocument()
      expect(screen.getByText('85 blocks')).toBeInTheDocument()
      expect(screen.getByText('42 blocks')).toBeInTheDocument()
    })

    test('renders rank numbers', () => {
      render(<TopBlockedSources sources={sampleSources} />)

      expect(screen.getByText('1.')).toBeInTheDocument()
      expect(screen.getByText('2.')).toBeInTheDocument()
      expect(screen.getByText('3.')).toBeInTheDocument()
    })
  })

  describe('bar visualization', () => {
    test('renders progress bars when 2 or more sources', () => {
      const { container } = render(
        <TopBlockedSources sources={sampleSources} />
      )

      const bars = container.querySelectorAll('.h-full.bg-red-500')
      expect(bars.length).toBe(sampleSources.length)
    })

    test('does not render progress bars when only 1 source', () => {
      const { container } = render(
        <TopBlockedSources sources={[{ src_ip: '192.168.1.100', count: 10 }]} />
      )

      const bars = container.querySelectorAll('.h-full.bg-red-500')
      expect(bars.length).toBe(0)
    })
  })

  describe('edge cases', () => {
    test('handles source with zero count', () => {
      render(
        <TopBlockedSources sources={[{ src_ip: '0.0.0.0', count: 0 }]} />
      )

      expect(screen.getByText('0 blocks')).toBeInTheDocument()
    })

    test('scales bar widths relative to max count', () => {
      const { container } = render(
        <TopBlockedSources
          sources={[
            { src_ip: '1.1.1.1', count: 200 },
            { src_ip: '2.2.2.2', count: 100 },
          ]}
        />
      )

      const bars = container.querySelectorAll('.h-full.bg-red-500')
      expect(bars.length).toBe(2)
    })
  })
})
