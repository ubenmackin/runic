import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import IPManager from './IPManager'

describe('IPManager', () => {
  const defaultProps = {
    peerId: 1,
    isManual: true,
    ips: [
      { id: 1, ip_address: '10.0.0.1', is_primary: true },
      { id: 2, ip_address: '10.0.0.2', is_primary: false },
    ],
    loading: false,
    onAddIP: vi.fn(),
    onDeleteIP: vi.fn(),
    agentVersion: undefined,
    latestAgentVersion: undefined,
    isAgentOutdated: false,
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('manual peer mode', () => {
    test('renders Secondary IP Addresses label', () => {
      render(<IPManager {...defaultProps} />)

      expect(screen.getByText('Secondary IP Addresses')).toBeInTheDocument()
    })

    test('renders IP addresses', () => {
      render(<IPManager {...defaultProps} />)

      expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
      expect(screen.getByText('10.0.0.2')).toBeInTheDocument()
    })

    test('renders PRIMARY badge for primary IP', () => {
      render(<IPManager {...defaultProps} />)

      expect(screen.getByText('PRIMARY')).toBeInTheDocument()
    })

    test('renders delete button for non-primary IPs', () => {
      render(<IPManager {...defaultProps} />)

      const deleteButtons = screen.getAllByTitle('Remove IP address')
      expect(deleteButtons.length).toBe(1) // Only one non-primary
    })

    test('renders input for adding new IP', () => {
      render(<IPManager {...defaultProps} />)

      expect(screen.getByPlaceholderText('e.g., 10.20.10.20')).toBeInTheDocument()
    })

    test('renders Add IP button', () => {
      render(<IPManager {...defaultProps} />)

      expect(screen.getByRole('button', { name: /add ip/i })).toBeInTheDocument()
    })

    test('Add IP button is disabled when input is empty', () => {
      render(<IPManager {...defaultProps} />)

      const addButton = screen.getByRole('button', { name: /add ip/i })
      expect(addButton).toBeDisabled()
    })

    test('calls onDeleteIP when delete button is clicked', async () => {
      const user = userEvent.setup()
      const handleDelete = vi.fn()

      render(<IPManager {...defaultProps} onDeleteIP={handleDelete} />)

      const deleteButton = screen.getByTitle('Remove IP address')
      await user.click(deleteButton)

      expect(handleDelete).toHaveBeenCalledWith(1, 2)
    })

    test('shows loading state', () => {
      render(<IPManager {...defaultProps} loading={true} />)

      expect(screen.getByText('Loading IPs...')).toBeInTheDocument()
    })

    test('shows empty message when no IPs', () => {
      render(<IPManager {...defaultProps} ips={[]} />)

      expect(screen.getByText('No additional IP addresses')).toBeInTheDocument()
    })

    test('filters out IPv6 addresses', () => {
      const ipsWithIPv6 = [
        { id: 1, ip_address: '10.0.0.1', is_primary: true },
        { id: 2, ip_address: 'fe80::1', is_primary: false },
      ]

      render(<IPManager {...defaultProps} ips={ipsWithIPv6} />)

      expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
      expect(screen.queryByText('fe80::1')).not.toBeInTheDocument()
    })

    test('Enter key in input triggers add IP', async () => {
      const user = userEvent.setup()
      const handleAdd = vi.fn().mockResolvedValue(undefined)

      render(<IPManager {...defaultProps} onAddIP={handleAdd} />)

      const input = screen.getByPlaceholderText('e.g., 10.20.10.20')
      await user.type(input, '10.20.10.20')
      await user.keyboard('{Enter}')

      expect(handleAdd).toHaveBeenCalledWith(1, '10.20.10.20')
    })
  })

  describe('agent peer mode', () => {
    test('renders IP Addresses label', () => {
      render(<IPManager {...defaultProps} isManual={false} />)

      expect(screen.getByText('IP Addresses')).toBeInTheDocument()
    })

    test('renders auto-detected message', () => {
      render(<IPManager {...defaultProps} isManual={false} />)

      expect(screen.getByText('Agent IPs are auto-detected and cannot be manually managed.')).toBeInTheDocument()
    })

    test('does not render add IP input', () => {
      render(<IPManager {...defaultProps} isManual={false} />)

      expect(screen.queryByPlaceholderText('e.g., 10.20.10.20')).not.toBeInTheDocument()
    })

    test('does not render delete buttons for agent IPs', () => {
      render(<IPManager {...defaultProps} isManual={false} />)

      expect(screen.queryByTitle('Remove IP address')).not.toBeInTheDocument()
    })

    test('shows Agent Version when provided', () => {
      render(<IPManager {...defaultProps} isManual={false} agentVersion="1.2.3" />)

      expect(screen.getByText('Agent Version')).toBeInTheDocument()
      expect(screen.getByText('v1.2.3')).toBeInTheDocument()
    })

    test('does not show Agent Version when undefined', () => {
      render(<IPManager {...defaultProps} isManual={false} />)

      expect(screen.queryByText('Agent Version')).not.toBeInTheDocument()
    })

    test('shows outdated badge when agent is outdated', () => {
      render(
        <IPManager
          {...defaultProps}
          isManual={false}
          agentVersion="1.0.0"
          latestAgentVersion="1.2.3"
          isAgentOutdated={true}
        />
      )

      expect(screen.getByText('v1.2.3 available')).toBeInTheDocument()
    })

    test('shows empty message when no IPs detected', () => {
      render(<IPManager {...defaultProps} isManual={false} ips={[]} />)

      expect(screen.getByText('No IP addresses detected')).toBeInTheDocument()
    })

    test('shows loading state', () => {
      render(<IPManager {...defaultProps} isManual={false} loading={true} />)

      expect(screen.getByText('Loading IPs...')).toBeInTheDocument()
    })
  })
})
