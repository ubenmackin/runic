import { render, screen } from '@testing-library/react'
import { describe, test, expect } from 'vitest'
import RecentActivityFeed from './RecentActivityFeed'

const sampleActivity = [
  {
    timestamp: new Date(Date.now() - 1 * 60 * 1000).toISOString(), // 1 min ago
    src_ip: '192.168.1.100',
    dst_ip: '10.0.0.1',
    protocol: 'TCP',
    hostname: 'web-server',
  },
  {
    timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(), // 5 min ago
    src_ip: '10.0.0.50',
    dst_ip: '172.16.0.1',
    protocol: 'UDP',
    hostname: null,
  },
  {
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(), // 2 hours ago
    src_ip: '203.0.113.5',
    dst_ip: '198.51.100.20',
    protocol: 'ICMP',
  },
]

describe('RecentActivityFeed', () => {
  describe('rendering', () => {
    test('renders header with title', () => {
      render(<RecentActivityFeed activity={[]} />)

      expect(screen.getByText('Recent Activity')).toBeInTheDocument()
    })

    test('renders empty state when activity array is empty', () => {
      render(<RecentActivityFeed activity={[]} />)

      expect(
        screen.getByText('No recent blocked events')
      ).toBeInTheDocument()
    })

    test('renders activity items', () => {
      render(<RecentActivityFeed activity={sampleActivity} />)

      expect(screen.getByText('192.168.1.100')).toBeInTheDocument()
      expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
      expect(screen.getByText('203.0.113.5')).toBeInTheDocument()
    })

    test('renders protocol badges for each activity item', () => {
      render(<RecentActivityFeed activity={sampleActivity} />)

      expect(screen.getByText('TCP')).toBeInTheDocument()
      expect(screen.getByText('UDP')).toBeInTheDocument()
      expect(screen.getByText('ICMP')).toBeInTheDocument()
    })

    test('renders direction arrow between IPs', () => {
      render(<RecentActivityFeed activity={sampleActivity.slice(0, 1)} />)

      expect(screen.getByText('→')).toBeInTheDocument()
    })
  })

  describe('relative time display', () => {
    test('displays "Just now" for activity within the last minute', () => {
      const activity = [
        {
          timestamp: new Date(Date.now() - 30 * 1000).toISOString(),
          src_ip: '1.1.1.1',
          dst_ip: '2.2.2.2',
          protocol: 'TCP',
        },
      ]

      render(<RecentActivityFeed activity={activity} />)

      expect(screen.getByText('Just now')).toBeInTheDocument()
    })

    test('displays minutes ago for recent activity', () => {
      render(<RecentActivityFeed activity={sampleActivity} />)

      expect(screen.getByText('1 min ago')).toBeInTheDocument()
      expect(screen.getByText('5 min ago')).toBeInTheDocument()
    })

    test('displays hours ago for older activity', () => {
      render(<RecentActivityFeed activity={sampleActivity} />)

      expect(screen.getByText('2h ago')).toBeInTheDocument()
    })

    test('displays days ago for very old activity', () => {
      const activity = [
        {
          timestamp: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
          src_ip: '1.1.1.1',
          dst_ip: '2.2.2.2',
          protocol: 'TCP',
        },
      ]

      render(<RecentActivityFeed activity={activity} />)

      expect(screen.getByText('3d ago')).toBeInTheDocument()
    })
  })

  describe('hostname display', () => {
    test('shows hostname when present', () => {
      render(<RecentActivityFeed activity={sampleActivity} />)

      expect(screen.getByText('web-server')).toBeInTheDocument()
    })

    test('does not show hostname when null', () => {
      render(<RecentActivityFeed activity={sampleActivity} />)

      // The second activity has hostname: null, so 'web-server' should only appear once
      const hostnameElements = screen.getAllByText('web-server')
      expect(hostnameElements.length).toBe(1)
    })
  })

  describe('edge cases', () => {
    test('renders multiple activity items with separators', () => {
      const { container } = render(
        <RecentActivityFeed activity={sampleActivity} />
      )

      // Each activity has a border-b class
      const items = container.querySelectorAll('.border-b')
      expect(items.length).toBeGreaterThanOrEqual(sampleActivity.length)
    })

    test('handles activity with empty timestamp', () => {
      const activity = [
        {
          timestamp: '',
          src_ip: '1.1.1.1',
          dst_ip: '2.2.2.2',
          protocol: 'TCP',
        },
      ]

      render(<RecentActivityFeed activity={activity} />)

      // NaN diff → falls through to "Just now" or some string
      expect(screen.getByText(/ago|Just now/)).toBeInTheDocument()
    })
  })
})
