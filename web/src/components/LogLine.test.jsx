import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import LogLine from './LogLine'

const createDropLog = (overrides = {}) => ({
  id: 1,
  timestamp: '2026-05-18T10:30:00.000Z',
  action: 'DROP',
  direction: 'IN',
  src_ip: '192.168.1.100',
  src_port: 443,
  dst_ip: '10.0.0.1',
  dst_port: 80,
  protocol: 'TCP',
  raw_line: '[RUNIC-DROP] IN=eth0 OUT= SRC=192.168.1.100...',
  hostname: 'gateway-1',
  ...overrides,
})

const createAcceptLog = (overrides = {}) => ({
  id: 2,
  timestamp: '2026-05-18T10:30:00.000Z',
  action: 'ACCEPT',
  direction: 'OUT',
  src_ip: '10.0.0.1',
  src_port: 12345,
  dst_ip: '8.8.8.8',
  dst_port: 53,
  protocol: 'UDP',
  raw_line: '[RUNIC-ACCEPT] OUT=eth0 IN= SRC=10.0.0.1...',
  hostname: null,
  ...overrides,
})

describe('LogLine', () => {
  describe('rendering', () => {
    test('renders timestamp in formatted form', () => {
      render(<LogLine log={createDropLog()} expanded={false} />)

      expect(screen.getByText(/2026-05-18/)).toBeInTheDocument()
    })

    test('renders action badge with DROP', () => {
      render(<LogLine log={createDropLog()} expanded={false} />)

      expect(screen.getByText('DROP')).toBeInTheDocument()
    })

    test('renders action badge with ACCEPT', () => {
      render(<LogLine log={createAcceptLog()} expanded={false} />)

      expect(screen.getByText('ACCEPT')).toBeInTheDocument()
    })

    test('renders direction icon for IN', () => {
      render(<LogLine log={createDropLog()} expanded={false} />)

      expect(screen.getByText('↓')).toBeInTheDocument()
    })

    test('renders direction icon for OUT', () => {
      render(<LogLine log={createAcceptLog()} expanded={false} />)

      expect(screen.getByText('↑')).toBeInTheDocument()
    })

    test('renders source IP with port', () => {
      render(<LogLine log={createDropLog()} expanded={false} />)

      expect(screen.getByText(/192.168.1.100:443/)).toBeInTheDocument()
    })

    test('renders destination IP with port', () => {
      render(<LogLine log={createDropLog()} expanded={false} />)

      expect(screen.getByText(/10.0.0.1:80/)).toBeInTheDocument()
    })

    test('renders protocol', () => {
      render(<LogLine log={createDropLog()} expanded={false} />)

      expect(screen.getByText('TCP')).toBeInTheDocument()
    })

    test('renders direction arrow', () => {
      render(<LogLine log={createDropLog()} expanded={false} />)

      const arrows = screen.getAllByText('→')
      expect(arrows.length).toBeGreaterThan(0)
    })

    test('handles missing timestamp gracefully', () => {
      render(
        <LogLine log={createDropLog({ timestamp: null })} expanded={false} />
      )

      expect(screen.getByText('—')).toBeInTheDocument()
    })
  })

  describe('expand/collapse', () => {
    test('is collapsed by default (uncontrolled)', () => {
      render(<LogLine log={createDropLog()} />)

      expect(screen.queryByText('Raw Kernel Log:')).not.toBeInTheDocument()
    })

    test('expands when clicked (uncontrolled)', async () => {
      const user = userEvent.setup()
      render(<LogLine log={createDropLog()} />)

      await user.click(screen.getByText('192.168.1.100:443'))

      expect(screen.getByText('Raw Kernel Log:')).toBeInTheDocument()
    })

    test('shows chevron state change when expanded', async () => {
      const user = userEvent.setup()
      render(<LogLine log={createDropLog()} />)

      const button = screen.getByRole('button')
      expect(button.querySelector('svg.lucide-chevron-right')).toBeTruthy()

      await user.click(button)
      expect(button.querySelector('svg.lucide-chevron-down')).toBeTruthy()
    })

    test('calls onToggle when expanded in controlled mode', async () => {
      const user = userEvent.setup()
      const handleToggle = vi.fn()

      render(
        <LogLine
          log={createDropLog({ id: 5 })}
          expanded={false}
          onToggle={handleToggle}
        />
      )

      await user.click(screen.getByRole('button'))

      expect(handleToggle).toHaveBeenCalledWith(5)
    })

    test('shows raw log line when expanded', async () => {
      const user = userEvent.setup()
      render(<LogLine log={createDropLog()} />)

      await user.click(screen.getByRole('button'))

      expect(
        screen.getByText('[RUNIC-DROP] IN=eth0 OUT= SRC=192.168.1.100...')
      ).toBeInTheDocument()
    })

    test('shows fallback when no raw_line', async () => {
      const user = userEvent.setup()
      render(<LogLine log={createDropLog({ raw_line: null })} />)

      await user.click(screen.getByRole('button'))

      expect(screen.getByText('No raw log available')).toBeInTheDocument()
    })
  })

  describe('craft policy button', () => {
    test('shows Craft Policy button for DROP when canEdit is true', async () => {
      const user = userEvent.setup()
      render(
        <LogLine
          log={createDropLog()}
          canEdit={true}
          onCraftPolicy={() => {}}
        />
      )

      await user.click(screen.getByRole('button'))

      expect(screen.getByText('Craft Policy')).toBeInTheDocument()
    })

    test('does not show Craft Policy button for ACCEPT', async () => {
      const user = userEvent.setup()
      render(
        <LogLine
          log={createAcceptLog()}
          canEdit={true}
          onCraftPolicy={() => {}}
        />
      )

      await user.click(screen.getByRole('button'))

      expect(screen.queryByText('Craft Policy')).not.toBeInTheDocument()
    })

    test('does not show Craft Policy button when canEdit is false', async () => {
      const user = userEvent.setup()
      render(
        <LogLine
          log={createDropLog()}
          canEdit={false}
          onCraftPolicy={() => {}}
        />
      )

      await user.click(screen.getByRole('button'))

      expect(screen.queryByText('Craft Policy')).not.toBeInTheDocument()
    })

    test('does not show Craft Policy button when onCraftPolicy is not provided', async () => {
      const user = userEvent.setup()
      render(<LogLine log={createDropLog()} canEdit={true} />)

      await user.click(screen.getByRole('button'))

      expect(screen.queryByText('Craft Policy')).not.toBeInTheDocument()
    })

    test('calls onCraftPolicy when Craft Policy button is clicked', async () => {
      const user = userEvent.setup()
      const handleCraft = vi.fn()
      const testLog = createDropLog({ id: 42 })

      render(
        <LogLine
          log={testLog}
          canEdit={true}
          onCraftPolicy={handleCraft}
        />
      )

      await user.click(screen.getByRole('button'))
      await user.click(screen.getByText('Craft Policy'))

      expect(handleCraft).toHaveBeenCalledWith(testLog)
    })
  })

  describe('hostname in expanded view', () => {
    test('shows hostname when present and expanded', async () => {
      const user = userEvent.setup()
      render(<LogLine log={createDropLog()} />)

      await user.click(screen.getByRole('button'))

      expect(screen.getByText(/Server: gateway-1/)).toBeInTheDocument()
    })

    test('does not show hostname when null', async () => {
      const user = userEvent.setup()
      render(<LogLine log={createAcceptLog()} />)

      await user.click(screen.getByRole('button'))

      expect(screen.queryByText(/Server:/)).not.toBeInTheDocument()
    })
  })

  describe('keyboard interaction', () => {
    test('toggles with Enter key', async () => {
      const user = userEvent.setup()
      render(<LogLine log={createDropLog()} />)

      const button = screen.getByRole('button')
      button.focus()
      await user.keyboard('{Enter}')

      expect(screen.getByText('Raw Kernel Log:')).toBeInTheDocument()
    })

    test('toggles with Space key', async () => {
      const user = userEvent.setup()
      render(<LogLine log={createDropLog()} />)

      const button = screen.getByRole('button')
      button.focus()
      await user.keyboard(' ')

      expect(screen.getByText('Raw Kernel Log:')).toBeInTheDocument()
    })
  })
})
