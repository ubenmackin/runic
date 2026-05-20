import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import PolicyFormModal from './PolicyFormModal'

// Mock SearchableSelect since it has complex async behavior
vi.mock('./SearchableSelect', () => ({
  default: ({ value, onChange, placeholder }) => (
    <select
      data-testid="mock-searchable-select"
      value={value || ''}
      onChange={(e) => onChange && onChange(e.target.value, 'peer')}
      aria-label={placeholder}
    >
      <option value="">Select...</option>
      <option value="1">Item 1</option>
      <option value="2">Item 2</option>
    </select>
  ),
}))

// Mock ToggleSwitch
vi.mock('./ToggleSwitch', () => ({
  default: ({ checked, onChange, 'aria-labelledby': ariaLabelledBy }) => (
    <button
      role="switch"
      aria-checked={checked}
      aria-labelledby={ariaLabelledBy}
      onClick={() => onChange(!checked)}
      data-testid="mock-toggle-switch"
    />
  ),
}))

// Mock InlineError
vi.mock('./InlineError', () => ({
  default: ({ message }) => message ? <span>{message}</span> : null,
}))

describe('PolicyFormModal', () => {
  const defaultFormData = {
    name: '',
    priority: 100,
    description: '',
    source_id: '',
    source_type: 'group',
    source_ip: '',
    target_id: '',
    target_type: 'peer',
    target_ip: '',
    service_id: '',
    action: 'ACCEPT',
    direction: 'forward',
    target_scope: 'both',
    enabled: true,
  }

  const defaultProps = {
    isOpen: true,
    onClose: vi.fn(),
    editItem: null,
    peerList: [],
    serviceList: [],
    groupList: [],
    specialTargetList: [],
    formData: defaultFormData,
    setFormData: vi.fn(),
    formErrors: {},
    activeTab: 'setup',
    setActiveTab: vi.fn(),
    showDescription: false,
    setShowDescription: vi.fn(),
    preview: null,
    previewLoading: false,
    onSubmit: vi.fn(),
    onPreview: vi.fn(),
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('rendering', () => {
    test('returns null when isOpen is false', () => {
      const { container } = render(
        <PolicyFormModal {...defaultProps} isOpen={false} />
      )

      expect(container.innerHTML).toBe('')
    })

    test('renders New Policy title when no editItem', () => {
      render(<PolicyFormModal {...defaultProps} />)

      expect(screen.getByText('New Policy')).toBeInTheDocument()
    })

    test('renders Edit Policy title when editItem is provided', () => {
      render(
        <PolicyFormModal {...defaultProps} editItem={{ id: 1, name: 'test' }} />
      )

      expect(screen.getByText('Edit Policy')).toBeInTheDocument()
    })

    test('renders Setup and Preview tabs', () => {
      render(<PolicyFormModal {...defaultProps} />)

      expect(screen.getByText('Setup')).toBeInTheDocument()
      expect(screen.getByText('Preview')).toBeInTheDocument()
    })

    test('renders Name input', () => {
      render(<PolicyFormModal {...defaultProps} />)

      expect(screen.getByText('Name')).toBeInTheDocument()
    })

    test('renders Priority input', () => {
      render(<PolicyFormModal {...defaultProps} />)

      expect(screen.getByText('Priority')).toBeInTheDocument()
    })

    test('renders Cancel button', () => {
      render(<PolicyFormModal {...defaultProps} />)

      expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument()
    })

    test('renders Create Policy button', () => {
      render(<PolicyFormModal {...defaultProps} />)

      expect(screen.getByRole('button', { name: /create policy/i })).toBeInTheDocument()
    })

    test('renders Save Changes button when editing', () => {
      render(
        <PolicyFormModal {...defaultProps} editItem={{ id: 1, name: 'test' }} />
      )

      expect(screen.getByRole('button', { name: /save changes/i })).toBeInTheDocument()
    })
  })

  describe('description toggle', () => {
    test('renders description toggle button', () => {
      render(<PolicyFormModal {...defaultProps} />)

      expect(screen.getByText('Description (Optional)')).toBeInTheDocument()
    })

    test('calls setShowDescription when description toggle is clicked', async () => {
      const user = userEvent.setup()
      const setShowDescription = vi.fn()

      render(<PolicyFormModal {...defaultProps} setShowDescription={setShowDescription} />)

      await user.click(screen.getByText('Description (Optional)'))

      expect(setShowDescription).toHaveBeenCalledWith(true)
    })
  })

  describe('action radio buttons', () => {
    test('renders ACCEPT action', () => {
      render(<PolicyFormModal {...defaultProps} />)

      expect(screen.getByText('ACCEPT')).toBeInTheDocument()
    })

    test('renders LOG+DROP action', () => {
      render(<PolicyFormModal {...defaultProps} />)

      expect(screen.getByText('LOG+DROP')).toBeInTheDocument()
    })
  })

  describe('target scope buttons', () => {
    test('renders scope options', () => {
      render(<PolicyFormModal {...defaultProps} />)

      expect(screen.getByText('Host + Docker')).toBeInTheDocument()
      expect(screen.getByText('Host Only')).toBeInTheDocument()
      expect(screen.getByText('Docker Only')).toBeInTheDocument()
    })
  })

  describe('preview tab', () => {
    test('renders preview content when activeTab is preview', () => {
      render(<PolicyFormModal {...defaultProps} activeTab="preview" />)

      expect(screen.getByText('Generated Rules')).toBeInTheDocument()
      expect(screen.getByText('Refresh')).toBeInTheDocument()
    })

    test('renders empty state when no preview available', () => {
      render(<PolicyFormModal {...defaultProps} activeTab="preview" />)

      expect(screen.getByText('Select source, service, and target to preview rules')).toBeInTheDocument()
    })
  })

  describe('accessibility', () => {
    test('has heading structure', () => {
      render(<PolicyFormModal {...defaultProps} />)

      expect(screen.getByRole('heading', { level: 3 })).toHaveTextContent('New Policy')
    })

    test('modal overlay has tabIndex for keyboard access', () => {
      render(<PolicyFormModal {...defaultProps} />)

      const overlay = document.querySelector('.fixed.inset-0')
      expect(overlay).toHaveAttribute('tabindex', '-1')
    })
  })
})
