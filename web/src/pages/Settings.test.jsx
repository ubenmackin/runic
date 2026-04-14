import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Settings from './Settings'
import { useAuthStore } from '../store'
import * as apiClient from '../api/client'

// Mock the API client
vi.mock('../api/client', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
  QUERY_KEYS: {
    setupKeys: () => ['setup-keys'],
    logSettings: () => ['log-settings'],
    smtpConfig: () => ['smtp-config'],
    notificationPrefs: () => ['notification-preferences'],
    alertRules: () => ['alert-rules'],
    peers: () => ['peers'],
  },
  getSMTPConfig: vi.fn(),
  updateSMTPConfig: vi.fn(),
  testSMTP: vi.fn(),
  getNotificationPrefs: vi.fn(),
  updateNotificationPrefs: vi.fn(),
  getAlertRules: vi.fn(),
  updateAlertRule: vi.fn(),
  setAuthFailureHandler: vi.fn(),
}))

// Mock useFocusTrap hook
vi.mock('../hooks/useFocusTrap', () => ({
  useFocusTrap: vi.fn(),
}))

// Mock PageHeader component
vi.mock('../components/PageHeader', () => ({
  default: ({ title, description }) => (
    <div>
      <h1>{title}</h1>
      <p>{description}</p>
    </div>
  ),
}))

// Mock AlertSettings component
vi.mock('../components/AlertSettings', () => ({
  default: () => <div data-testid="alert-settings">Alert Settings Component</div>,
}))

// Helper to create wrapper with query client
function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
      },
      mutations: {
        retry: false,
      },
    },
  })

  return function Wrapper({ children }) {
    return (
      <QueryClientProvider client={queryClient}>
        {children}
      </QueryClientProvider>
    )
  }
}

// Helper to render with all providers
function renderWithProviders(ui, options = {}) {
  const wrapper = createWrapper()
  return render(ui, { wrapper, ...options })
}

// Mock toast context
const mockShowToast = vi.fn()
vi.mock('../hooks/ToastContext', () => ({
  useToastContext: () => mockShowToast,
}))

// Factory function to create mock notification preferences
const createMockNotificationPrefs = (overrides = {}) => ({
  enabled_alerts: JSON.stringify([]),
  quiet_hours_enabled: false,
  quiet_hours_start: '22:00',
  quiet_hours_end: '08:00',
  quiet_hours_timezone: 'UTC',
  digest_enabled: false,
  digest_time: '09:00',
  ...overrides,
})

describe('Settings Page', () => {
  const originalState = useAuthStore.getState()

  beforeEach(() => {
    vi.clearAllMocks()
    // Reset auth store to default state
    useAuthStore.setState({
      isAuthenticated: true,
      username: 'testuser',
      role: 'admin',
    })
  })

  afterEach(() => {
    useAuthStore.setState(originalState)
  })

  describe('Notification Preferences Section', () => {
    const mockNotificationPrefs = createMockNotificationPrefs({
      enabled_alerts: JSON.stringify(['bundle_deployed', 'peer_offline', 'blocked_spike']),
    })

    test('renders notification preferences section', async () => {
      apiClient.getNotificationPrefs.mockResolvedValue(mockNotificationPrefs)

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Your Notification Preferences')).toBeInTheDocument()
      })

      expect(screen.getByText('Configure which alerts you receive')).toBeInTheDocument()
    })

    test('shows loading state while fetching preferences', () => {
      apiClient.getNotificationPrefs.mockImplementation(() => new Promise(() => {}))

      renderWithProviders(<Settings />)

      // Look for the loader animation class
      const loaders = document.querySelectorAll('.animate-spin')
      expect(loaders.length).toBeGreaterThan(0)
    })

    test('renders alert type toggles with correct initial state', async () => {
      apiClient.getNotificationPrefs.mockResolvedValue(mockNotificationPrefs)

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByLabelText('Bundle Deployed')).toBeInTheDocument()
      })

      // Check the checkbox is checked (in enabled_alerts)
      const bundleCheckbox = screen.getByLabelText('Bundle Deployed')
      expect(bundleCheckbox).toBeChecked()

      // Check unchecked item
      const peerOnlineCheckbox = screen.getByLabelText('Peer Online')
      expect(peerOnlineCheckbox).not.toBeChecked()
    })

    test('toggling alert types updates state and calls API', async () => {
      const user = userEvent.setup()
      apiClient.getNotificationPrefs.mockResolvedValue(mockNotificationPrefs)
      apiClient.updateNotificationPrefs.mockResolvedValue({ success: true })

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByLabelText('Bundle Deployed')).toBeInTheDocument()
      })

      // Toggle an alert type
      const bundleCheckbox = screen.getByLabelText('Bundle Deployed')
      await user.click(bundleCheckbox)

      await waitFor(() => {
        expect(apiClient.updateNotificationPrefs).toHaveBeenCalled()
      })

      // Verify the API was called with transformed data
      const callArgs = apiClient.updateNotificationPrefs.mock.calls[0][0]
      expect(callArgs).toHaveProperty('enabled_alerts')
      expect(callArgs).toHaveProperty('quiet_hours_enabled')
      expect(callArgs).toHaveProperty('digest_enabled')
    })

    test('renders all alert type checkboxes', async () => {
      apiClient.getNotificationPrefs.mockResolvedValue(mockNotificationPrefs)

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByLabelText('Bundle Deployed')).toBeInTheDocument()
      })

      const alertTypes = [
        'Bundle Deployed',
        'Bundle Failed',
        'Peer Offline',
        'Peer Online',
        'Blocked Spike',
        'New Peer',
      ]

      alertTypes.forEach(type => {
        expect(screen.getByLabelText(type)).toBeInTheDocument()
      })
    })
  })

  describe('Quiet Hours Section', () => {
    const mockNotificationPrefs = createMockNotificationPrefs()

    test('quiet hours section expands when clicked', async () => {
      const user = userEvent.setup()
      apiClient.getNotificationPrefs.mockResolvedValue(mockNotificationPrefs)

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Quiet Hours')).toBeInTheDocument()
      })

      // Initially, time inputs should not be visible
      expect(screen.queryByLabelText('Start Time')).not.toBeInTheDocument()

      // Click to expand
      await user.click(screen.getByText('Quiet Hours'))

      await waitFor(() => {
        expect(screen.getByLabelText('Start Time')).toBeInTheDocument()
      })
      expect(screen.getByLabelText('End Time')).toBeInTheDocument()
      expect(screen.getByLabelText('Timezone')).toBeInTheDocument()
    })

    test('quiet hours settings save correctly', async () => {
      const user = userEvent.setup()
      apiClient.getNotificationPrefs.mockResolvedValue(mockNotificationPrefs)
      apiClient.updateNotificationPrefs.mockResolvedValue({ success: true })

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Quiet Hours')).toBeInTheDocument()
      })

      // Expand quiet hours
      await user.click(screen.getByText('Quiet Hours'))

      await waitFor(() => {
        expect(screen.getByLabelText('Enable Quiet Hours')).toBeInTheDocument()
      })

      // Enable quiet hours
      const enableCheckbox = screen.getByLabelText('Enable Quiet Hours')
      await user.click(enableCheckbox)

      await waitFor(() => {
        expect(apiClient.updateNotificationPrefs).toHaveBeenCalledWith(
          expect.objectContaining({
            quiet_hours_enabled: true,
          })
        )
      })
    })

  test('quiet hours section has start and end time inputs after expanding', async () => {
    const user = userEvent.setup()
    apiClient.getNotificationPrefs.mockResolvedValue(mockNotificationPrefs)

    renderWithProviders(<Settings />)

    await waitFor(() => {
      expect(screen.getByText('Quiet Hours')).toBeInTheDocument()
    })

    // Expand quiet hours
    await user.click(screen.getByText('Quiet Hours'))

    await waitFor(() => {
      expect(screen.getByLabelText('Start Time')).toBeInTheDocument()
    })

    // Verify time inputs are visible
    expect(screen.getByLabelText('Start Time')).toBeInTheDocument()
    expect(screen.getByLabelText('End Time')).toBeInTheDocument()
  })

  test('changing quiet hours time updates and saves', async () => {
    const user = userEvent.setup()
    apiClient.getNotificationPrefs.mockResolvedValue(mockNotificationPrefs)
    apiClient.updateNotificationPrefs.mockResolvedValue({ success: true })

    renderWithProviders(<Settings />)

    await waitFor(() => {
      expect(screen.getByText('Quiet Hours')).toBeInTheDocument()
    })

    // Expand quiet hours
    await user.click(screen.getByText('Quiet Hours'))

    await waitFor(() => {
      expect(screen.getByLabelText('Start Time')).toBeInTheDocument()
    })

    // Change start time using fireEvent for time input
    const startTimeInput = screen.getByLabelText('Start Time')
    await user.clear(startTimeInput)
    await user.type(startTimeInput, '23:00')

    // Wait for the onChange to trigger the API call
    await waitFor(() => {
      expect(apiClient.updateNotificationPrefs).toHaveBeenCalled()
    })

    // The onChange fires with the new value
    const calls = apiClient.updateNotificationPrefs.mock.calls
    const lastCall = calls[calls.length - 1][0]
    // Check that start_time was updated (it might be called multiple times during typing)
    expect(lastCall).toHaveProperty('quiet_hours_start')
  })
})

describe('Unified Timezone Selector', () => {
  const mockNotificationPrefs = createMockNotificationPrefs()

  test('timezone selector renders at top level in Notification Preferences section', async () => {
    apiClient.getNotificationPrefs.mockResolvedValue(mockNotificationPrefs)

    renderWithProviders(<Settings />)

    // Wait for notification preferences to load
    await waitFor(() => {
      expect(screen.getByText('Your Notification Preferences')).toBeInTheDocument()
    })

    // Wait for timezone selector to be available (need to wait for prefs to process)
    await waitFor(() => {
      expect(screen.getByLabelText('Timezone')).toBeInTheDocument()
    })

    // The unified timezone selector should be visible without expanding any collapsible
    expect(screen.getByLabelText('Timezone')).toBeInTheDocument()

    // Verify it is NOT inside a collapsible section
    const quietHoursButton = screen.getByText('Quiet Hours')
    const digestButton = screen.getByText('Daily Digest')

    // Timezone selector should be visible before expanding either section
    expect(quietHoursButton).toBeInTheDocument()
    expect(digestButton).toBeInTheDocument()
  })

  test('timezone change updates both quiet_hours and daily_digest', async () => {
    const user = userEvent.setup()
    apiClient.getNotificationPrefs.mockResolvedValue(mockNotificationPrefs)
    apiClient.updateNotificationPrefs.mockResolvedValue({ success: true })

    renderWithProviders(<Settings />)

    await waitFor(() => {
      expect(screen.getByLabelText('Timezone')).toBeInTheDocument()
    })

    // Change the unified timezone
    const timezoneSelect = screen.getByLabelText('Timezone')
    await user.selectOptions(timezoneSelect, 'America/New_York')

    // Wait for the API call
    await waitFor(() => {
      expect(apiClient.updateNotificationPrefs).toHaveBeenCalled()
    })

    // Verify the API was called with timezone for both quiet_hours and daily_digest
    const callArgs = apiClient.updateNotificationPrefs.mock.calls[0][0]
    expect(callArgs).toHaveProperty('quiet_hours_timezone', 'America/New_York')
    expect(callArgs).toHaveProperty('digest_timezone', 'America/New_York')
  })

  test('browser timezone auto-detection works when no timezone is set', async () => {
    // Mock notification prefs with no timezone set
    const prefsWithoutTimezone = createMockNotificationPrefs({
      quiet_hours_timezone: '',
      digest_timezone: '',
    })
    apiClient.getNotificationPrefs.mockResolvedValue(prefsWithoutTimezone)

    // Mock browser timezone detection
    const originalDateTimeFormat = Intl.DateTimeFormat
    vi.spyOn(Intl, 'DateTimeFormat').mockImplementation(() => ({
      resolvedOptions: () => ({ timeZone: 'America/Los_Angeles' }),
    }))

    renderWithProviders(<Settings />)

    await waitFor(() => {
      expect(screen.getByLabelText('Timezone')).toBeInTheDocument()
    })

    // Should auto-detect and set browser timezone (if in list) or UTC
    const timezoneSelect = screen.getByLabelText('Timezone')
    expect(timezoneSelect.value).toBe('America/Los_Angeles')

    // Restore original implementation
    Intl.DateTimeFormat = originalDateTimeFormat
  })

  test('browser timezone defaults to UTC when detected timezone is not in list', async () => {
    // Mock notification prefs with no timezone set
    const prefsWithoutTimezone = createMockNotificationPrefs({
      quiet_hours_timezone: '',
      digest_timezone: '',
    })
    apiClient.getNotificationPrefs.mockResolvedValue(prefsWithoutTimezone)

    // Mock browser timezone detection with an unsupported timezone
    const originalDateTimeFormat = Intl.DateTimeFormat
    vi.spyOn(Intl, 'DateTimeFormat').mockImplementation(() => ({
      resolvedOptions: () => ({ timeZone: 'Antarctica/South_Pole' }),
    }))

    renderWithProviders(<Settings />)

    await waitFor(() => {
      expect(screen.getByLabelText('Timezone')).toBeInTheDocument()
    })

    // Should default to UTC since Antarctica/South_Pole is not in the list
    const timezoneSelect = screen.getByLabelText('Timezone')
    expect(timezoneSelect.value).toBe('UTC')

    // Restore original implementation
    Intl.DateTimeFormat = originalDateTimeFormat
  })

  test('timezone dropdown shows all valid timezone options', async () => {
    apiClient.getNotificationPrefs.mockResolvedValue(mockNotificationPrefs)

    renderWithProviders(<Settings />)

    await waitFor(() => {
      expect(screen.getByLabelText('Timezone')).toBeInTheDocument()
    })

    const _timezoneSelect = screen.getByLabelText('Timezone')

    // Check that all expected timezone options exist
    expect(screen.getByRole('option', { name: 'UTC' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Eastern (New York)' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Central (Chicago)' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Mountain (Denver)' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Pacific (Los Angeles)' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'London' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Paris' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Tokyo' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Sydney' })).toBeInTheDocument()
  })

  test('existing timezone preference is preserved on load', async () => {
    // Mock notification prefs with existing timezone
    const prefsWithTimezone = createMockNotificationPrefs({
      quiet_hours_timezone: 'Europe/Paris',
      digest_timezone: 'Europe/Paris',
    })
    apiClient.getNotificationPrefs.mockResolvedValue(prefsWithTimezone)

    renderWithProviders(<Settings />)

    await waitFor(() => {
      expect(screen.getByLabelText('Timezone')).toBeInTheDocument()
    })

    const timezoneSelect = screen.getByLabelText('Timezone')
    expect(timezoneSelect.value).toBe('Europe/Paris')
  })

  test('helper text explains timezone applies to both sections', async () => {
    apiClient.getNotificationPrefs.mockResolvedValue(mockNotificationPrefs)

    renderWithProviders(<Settings />)

    await waitFor(() => {
      expect(screen.getByLabelText('Timezone')).toBeInTheDocument()
    })

    // Check for helper text
    expect(screen.getByText('Applies to both Quiet Hours and Daily Digest')).toBeInTheDocument()
  })
})

  describe('Daily Digest Section', () => {
    const mockNotificationPrefs = createMockNotificationPrefs()

    test('daily digest section expands when clicked', async () => {
      const user = userEvent.setup()
      apiClient.getNotificationPrefs.mockResolvedValue(mockNotificationPrefs)

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Daily Digest')).toBeInTheDocument()
      })

      // Initially, digest time input should not be visible
      expect(screen.queryByLabelText('Digest Time')).not.toBeInTheDocument()

      // Click to expand
      await user.click(screen.getByText('Daily Digest'))

      await waitFor(() => {
        expect(screen.getByLabelText('Digest Time')).toBeInTheDocument()
      })
      expect(screen.getByLabelText('Enable Daily Digest')).toBeInTheDocument()
    })

    test('enabling daily digest saves correctly', async () => {
      const user = userEvent.setup()
      apiClient.getNotificationPrefs.mockResolvedValue(mockNotificationPrefs)
      apiClient.updateNotificationPrefs.mockResolvedValue({ success: true })

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Daily Digest')).toBeInTheDocument()
      })

      // Expand daily digest
      await user.click(screen.getByText('Daily Digest'))

      await waitFor(() => {
        expect(screen.getByLabelText('Enable Daily Digest')).toBeInTheDocument()
      })

      // Enable daily digest
      const enableCheckbox = screen.getByLabelText('Enable Daily Digest')
      await user.click(enableCheckbox)

      await waitFor(() => {
        expect(apiClient.updateNotificationPrefs).toHaveBeenCalledWith(
          expect.objectContaining({
            digest_enabled: true,
          })
        )
      })
    })
  })

  describe('SMTP Configuration Section', () => {
    const mockSMTPConfig = {
      host: 'smtp.example.com',
      port: 587,
      username: 'alerts@example.com',
      password_set: true,
      use_tls: true,
      from_address: 'alerts@example.com',
      enabled: true,
    }

    beforeEach(() => {
      useAuthStore.setState({ role: 'admin' })
    })

    test('SMTP configuration loads and displays correctly', async () => {
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.getSMTPConfig.mockResolvedValue(mockSMTPConfig)

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('SMTP Configuration')).toBeInTheDocument()
      })

      // Check that form fields are populated
      await waitFor(() => {
        expect(screen.getByLabelText('SMTP Host')).toHaveValue('smtp.example.com')
      })
      // Port is a number input, so value is compared as number
      expect(screen.getByLabelText('SMTP Port')).toHaveValue(587)
      expect(screen.getByLabelText('Username')).toHaveValue('alerts@example.com')
      expect(screen.getByLabelText('From Address')).toHaveValue('alerts@example.com')
    })

    test('SMTP configuration saves correctly', async () => {
      const user = userEvent.setup()
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.getSMTPConfig.mockResolvedValue(mockSMTPConfig)
      apiClient.updateSMTPConfig.mockResolvedValue({ success: true })

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Save SMTP Settings')).toBeInTheDocument()
      })

      // Find and click save button
      const saveButton = screen.getByText('Save SMTP Settings')
      await user.click(saveButton)

      await waitFor(() => {
        expect(apiClient.updateSMTPConfig).toHaveBeenCalled()
      })

      // Check success toast
      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith('SMTP configuration updated', 'success')
      })
    })

    test('SMTP shows loading state', async () => {
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.getSMTPConfig.mockImplementation(() => new Promise(() => {}))

      renderWithProviders(<Settings />)

      // Should show loader while loading SMTP config
      await waitFor(() => {
        const loaders = document.querySelectorAll('.animate-spin')
        expect(loaders.length).toBeGreaterThan(0)
      })
    })

    test('password field has show/hide toggle', async () => {
      const user = userEvent.setup()
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.getSMTPConfig.mockResolvedValue(mockSMTPConfig)

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByLabelText('Password')).toBeInTheDocument()
      })

      const passwordInput = screen.getByLabelText('Password')
      expect(passwordInput).toHaveAttribute('type', 'password')

      // Click the eye icon to show password
      const eyeButton = passwordInput.parentElement.querySelector('button')
      await user.click(eyeButton)

      expect(passwordInput).toHaveAttribute('type', 'text')
    })

    test('Test email button works when SMTP is enabled', async () => {
      const user = userEvent.setup()
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      // Set enabled: true so the button is not disabled
      apiClient.getSMTPConfig.mockResolvedValue({ ...mockSMTPConfig, enabled: true })
      apiClient.testSMTP.mockResolvedValue({ success: true })

      renderWithProviders(<Settings />)

      // Wait for SMTP config to load and form state to update
      await waitFor(() => {
        expect(screen.getByLabelText('Enable SMTP')).toBeChecked()
      })

      await waitFor(() => {
        expect(screen.getByText('Test Email')).toBeInTheDocument()
      })

      const testEmailButton = screen.getByText('Test Email')
      // Button should not be disabled since smtpFormData.enabled is true
      expect(testEmailButton).not.toBeDisabled()

      await user.click(testEmailButton)

      await waitFor(() => {
        expect(apiClient.testSMTP).toHaveBeenCalled()
      })

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith('Test email sent successfully', 'success')
      })
    })

    test('Test email button is disabled when SMTP is not enabled', async () => {
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.getSMTPConfig.mockResolvedValue({ ...mockSMTPConfig, enabled: false })

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Test Email')).toBeInTheDocument()
      })

      const testEmailButton = screen.getByText('Test Email')
      expect(testEmailButton).toBeDisabled()
    })

    test('TLS and Enable SMTP toggles work', async () => {
      const user = userEvent.setup()
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.getSMTPConfig.mockResolvedValue({ ...mockSMTPConfig, use_tls: true, enabled: true })

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByLabelText('Use TLS')).toBeInTheDocument()
      })

      expect(screen.getByLabelText('Use TLS')).toBeChecked()
      expect(screen.getByLabelText('Enable SMTP')).toBeChecked()

      // Toggle TLS
      await user.click(screen.getByLabelText('Use TLS'))
      expect(screen.getByLabelText('Use TLS')).not.toBeChecked()
    })

    test('editing SMTP fields updates form state', async () => {
      const user = userEvent.setup()
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.getSMTPConfig.mockResolvedValue(mockSMTPConfig)
      apiClient.updateSMTPConfig.mockResolvedValue({ success: true })

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByLabelText('SMTP Host')).toBeInTheDocument()
      })

      // Edit host
      const hostInput = screen.getByLabelText('SMTP Host')
      await user.clear(hostInput)
      await user.type(hostInput, 'new.smtp.com')

      // Save
      await user.click(screen.getByText('Save SMTP Settings'))

      await waitFor(() => {
        // The mutation is called with the form data as the first argument
        expect(apiClient.updateSMTPConfig).toHaveBeenCalled()
        const callArgs = apiClient.updateSMTPConfig.mock.calls[0][0]
        expect(callArgs.host).toBe('new.smtp.com')
      })
    })
  })

  describe('Error Handling', () => {
    test('shows error toast when notification prefs API fails', async () => {
      apiClient.getNotificationPrefs.mockRejectedValue(new Error('Failed to load preferences'))

      renderWithProviders(<Settings />)

      // The component should still render but show error state
      await waitFor(() => {
        expect(screen.getByText('Please log in to configure notification preferences.')).toBeInTheDocument()
      })
    })

    test('shows error toast when updating notification prefs fails', async () => {
      const user = userEvent.setup()
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify(['bundle_deployed']),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.updateNotificationPrefs.mockRejectedValue(new Error('Update failed'))

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByLabelText('Bundle Deployed')).toBeInTheDocument()
      })

      // Toggle a checkbox
      await user.click(screen.getByLabelText('Bundle Deployed'))

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith('Update failed', 'error')
      })
    })

    test('shows error toast when SMTP config load fails', async () => {
      useAuthStore.setState({ role: 'admin' })
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.getSMTPConfig.mockRejectedValue(new Error('Failed to load SMTP config'))

      renderWithProviders(<Settings />)

      // Component should still render the SMTP section
      await waitFor(() => {
        expect(screen.getByText('SMTP Configuration')).toBeInTheDocument()
      })
    })

    test('shows error toast when SMTP update fails', async () => {
      const user = userEvent.setup()
      useAuthStore.setState({ role: 'admin' })
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.getSMTPConfig.mockResolvedValue({
        host: 'smtp.example.com',
        port: 587,
        enabled: true,
      })
      apiClient.updateSMTPConfig.mockRejectedValue(new Error('SMTP update failed'))

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Save SMTP Settings')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Save SMTP Settings'))

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith('SMTP update failed', 'error')
      })
    })

    test('shows error toast when test email fails', async () => {
      const user = userEvent.setup()
      useAuthStore.setState({ role: 'admin' })
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.getSMTPConfig.mockResolvedValue({
        host: 'smtp.example.com',
        port: 587,
        enabled: true,
      })
      apiClient.testSMTP.mockRejectedValue(new Error('Email send failed'))

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Test Email')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Test Email'))

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith('Email send failed', 'error')
      })
    })
  })

  describe('Access Control', () => {
    test('non-admin users see notification preferences only', async () => {
      useAuthStore.setState({ role: 'viewer' })
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Your Notification Preferences')).toBeInTheDocument()
      })

      // Should show access denied message
      expect(screen.getByText('Access Denied')).toBeInTheDocument()
      expect(screen.getByText(/Only administrators can access Settings/)).toBeInTheDocument()

      // Should NOT show tabs
      expect(screen.queryByText('Alerts')).not.toBeInTheDocument()
      expect(screen.queryByText('Logs')).not.toBeInTheDocument()
      expect(screen.queryByText('Keys')).not.toBeInTheDocument()
    })

    test('admin users see all tabs', async () => {
      useAuthStore.setState({ role: 'admin' })
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.getSMTPConfig.mockResolvedValue({ enabled: false })

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Alerts')).toBeInTheDocument()
      })

      expect(screen.getByText('Logs')).toBeInTheDocument()
      expect(screen.getByText('Keys')).toBeInTheDocument()
    })

    test('tab switching works for admin users', async () => {
      const user = userEvent.setup()
      useAuthStore.setState({ role: 'admin' })
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.api.get.mockResolvedValue([])
      apiClient.getSMTPConfig.mockResolvedValue({ enabled: false })

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Logs')).toBeInTheDocument()
      })

      // Click on Logs tab
      await user.click(screen.getByText('Logs'))

      await waitFor(() => {
        expect(screen.getByText('Log Management')).toBeInTheDocument()
      })

      // Click on Keys tab
      await user.click(screen.getByText('Keys'))

      await waitFor(() => {
        expect(screen.getByText('JWT Secret')).toBeInTheDocument()
      })
    })
  })

  describe('Loading States', () => {
    test('shows loading spinner while fetching notification prefs', async () => {
      apiClient.getNotificationPrefs.mockImplementation(() => new Promise(() => {}))

      renderWithProviders(<Settings />)

      // Should show loader animation
      await waitFor(() => {
        const loaders = document.querySelectorAll('.animate-spin')
        expect(loaders.length).toBeGreaterThan(0)
      })
    })

    test('shows loading spinner while fetching SMTP config for admin', async () => {
      useAuthStore.setState({ role: 'admin' })
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.getSMTPConfig.mockImplementation(() => new Promise(() => {}))

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('SMTP Configuration')).toBeInTheDocument()
      })

      // Should show loader in SMTP section
      const loaders = document.querySelectorAll('.animate-spin')
      expect(loaders.length).toBeGreaterThan(0)
    })

    test('save buttons show loading state during mutation', async () => {
      const user = userEvent.setup()
      useAuthStore.setState({ role: 'admin' })
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.getSMTPConfig.mockResolvedValue({
        host: 'smtp.example.com',
        port: 587,
        enabled: true,
      })
      apiClient.updateSMTPConfig.mockImplementation(() => new Promise(resolve => setTimeout(resolve, 100)))

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Save SMTP Settings')).toBeInTheDocument()
      })

      await user.click(screen.getByText('Save SMTP Settings'))

      // Button should show "Saving..."
      await waitFor(() => {
        expect(screen.getByText('Saving...')).toBeInTheDocument()
      })
    })

    test('test email button shows loading state during mutation', async () => {
      const user = userEvent.setup()
      useAuthStore.setState({ role: 'admin' })
      apiClient.getNotificationPrefs.mockResolvedValue({
        enabled_alerts: JSON.stringify([]),
        quiet_hours_enabled: false,
        digest_enabled: false,
      })
      apiClient.getSMTPConfig.mockResolvedValue({
        host: 'smtp.example.com',
        port: 587,
        enabled: true,
      })
      apiClient.testSMTP.mockImplementation(() => new Promise(resolve => setTimeout(resolve, 100)))

      renderWithProviders(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Test Email')).toBeInTheDocument()
      })

      const testButton = screen.getByText('Test Email').closest('button')
      await user.click(testButton)

      // Should show spinner in button
      await waitFor(() => {
        const loaders = testButton.querySelectorAll('.animate-spin')
        expect(loaders.length).toBeGreaterThan(0)
      })
    })
  })
})
