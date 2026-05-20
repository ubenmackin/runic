import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import NotificationPrefsForm from './NotificationPrefsForm'

describe('NotificationPrefsForm', () => {
  const defaultPrefs = {
    quiet_hours: {
      enabled: false,
      start_time: '22:00',
      end_time: '08:00',
    },
    daily_digest: {
      enabled: false,
      time: '09:00',
    },
  }

  describe('rendering', () => {
    test('renders timezone select', () => {
      render(
        <NotificationPrefsForm
          prefs={defaultPrefs}
          unifiedTimezone="UTC"
          loading={false}
          error={null}
          showQuietHours={false}
          setShowQuietHours={() => {}}
          showDigest={false}
          setShowDigest={() => {}}
          onQuietHoursChange={() => {}}
          onDigestChange={() => {}}
          onUnifiedTimezoneChange={() => {}}
        />
      )

      expect(screen.getByText('Timezone')).toBeInTheDocument()
    })

    test('renders timezone options', () => {
      render(
        <NotificationPrefsForm
          prefs={defaultPrefs}
          unifiedTimezone="UTC"
          loading={false}
          error={null}
          showQuietHours={false}
          setShowQuietHours={() => {}}
          showDigest={false}
          setShowDigest={() => {}}
          onQuietHoursChange={() => {}}
          onDigestChange={() => {}}
          onUnifiedTimezoneChange={() => {}}
        />
      )

      const select = screen.getByDisplayValue('UTC')
      expect(select).toBeInTheDocument()
    })

    test('renders Quiet Hours section header', () => {
      render(
        <NotificationPrefsForm
          prefs={defaultPrefs}
          unifiedTimezone="UTC"
          loading={false}
          error={null}
          showQuietHours={false}
          setShowQuietHours={() => {}}
          showDigest={false}
          setShowDigest={() => {}}
          onQuietHoursChange={() => {}}
          onDigestChange={() => {}}
          onUnifiedTimezoneChange={() => {}}
        />
      )

      expect(screen.getByText('Quiet Hours')).toBeInTheDocument()
    })

    test('renders Daily Digest section header', () => {
      render(
        <NotificationPrefsForm
          prefs={defaultPrefs}
          unifiedTimezone="UTC"
          loading={false}
          error={null}
          showQuietHours={false}
          setShowQuietHours={() => {}}
          showDigest={false}
          setShowDigest={() => {}}
          onQuietHoursChange={() => {}}
          onDigestChange={() => {}}
          onUnifiedTimezoneChange={() => {}}
        />
      )

      expect(screen.getByText('Daily Digest')).toBeInTheDocument()
    })
  })

  describe('loading state', () => {
    test('renders loading spinner when loading is true', () => {
      const { container } = render(
        <NotificationPrefsForm
          prefs={null}
          unifiedTimezone="UTC"
          loading={true}
          error={null}
          showQuietHours={false}
          setShowQuietHours={() => {}}
          showDigest={false}
          setShowDigest={() => {}}
          onQuietHoursChange={() => {}}
          onDigestChange={() => {}}
          onUnifiedTimezoneChange={() => {}}
        />
      )

      const spinner = container.querySelector('.animate-spin')
      expect(spinner).toBeInTheDocument()
    })
  })

  describe('error state', () => {
    test('renders error message when error is provided', () => {
      render(
        <NotificationPrefsForm
          prefs={null}
          unifiedTimezone="UTC"
          loading={false}
          error="Not authenticated"
          showQuietHours={false}
          setShowQuietHours={() => {}}
          showDigest={false}
          setShowDigest={() => {}}
          onQuietHoursChange={() => {}}
          onDigestChange={() => {}}
          onUnifiedTimezoneChange={() => {}}
        />
      )

      expect(screen.getByText('Please log in to configure notification preferences.')).toBeInTheDocument()
    })
  })

  describe('null prefs', () => {
    test('returns null when prefs is null and not loading/error', () => {
      const { container } = render(
        <NotificationPrefsForm
          prefs={null}
          unifiedTimezone="UTC"
          loading={false}
          error={null}
          showQuietHours={false}
          setShowQuietHours={() => {}}
          showDigest={false}
          setShowDigest={() => {}}
          onQuietHoursChange={() => {}}
          onDigestChange={() => {}}
          onUnifiedTimezoneChange={() => {}}
        />
      )

      expect(container.innerHTML).toBe('')
    })
  })

  describe('quiet hours section', () => {
    test('shows quiet hours content when expanded', () => {
      render(
        <NotificationPrefsForm
          prefs={defaultPrefs}
          unifiedTimezone="UTC"
          loading={false}
          error={null}
          showQuietHours={true}
          setShowQuietHours={() => {}}
          showDigest={false}
          setShowDigest={() => {}}
          onQuietHoursChange={() => {}}
          onDigestChange={() => {}}
          onUnifiedTimezoneChange={() => {}}
        />
      )

      expect(screen.getByText('Enable Quiet Hours')).toBeInTheDocument()
      expect(screen.getByText('Start Time')).toBeInTheDocument()
      expect(screen.getByText('End Time')).toBeInTheDocument()
    })

    test('hides quiet hours content when collapsed', () => {
      render(
        <NotificationPrefsForm
          prefs={defaultPrefs}
          unifiedTimezone="UTC"
          loading={false}
          error={null}
          showQuietHours={false}
          setShowQuietHours={() => {}}
          showDigest={false}
          setShowDigest={() => {}}
          onQuietHoursChange={() => {}}
          onDigestChange={() => {}}
          onUnifiedTimezoneChange={() => {}}
        />
      )

      expect(screen.queryByText('Enable Quiet Hours')).not.toBeInTheDocument()
    })

    test('toggle button calls setShowQuietHours', async () => {
      const user = userEvent.setup()
      const setShowQuietHours = vi.fn()

      render(
        <NotificationPrefsForm
          prefs={defaultPrefs}
          unifiedTimezone="UTC"
          loading={false}
          error={null}
          showQuietHours={false}
          setShowQuietHours={setShowQuietHours}
          showDigest={false}
          setShowDigest={() => {}}
          onQuietHoursChange={() => {}}
          onDigestChange={() => {}}
          onUnifiedTimezoneChange={() => {}}
        />
      )

      await user.click(screen.getByText('Quiet Hours'))

      expect(setShowQuietHours).toHaveBeenCalledWith(true)
    })
  })

  describe('daily digest section', () => {
    test('shows digest content when expanded', () => {
      render(
        <NotificationPrefsForm
          prefs={defaultPrefs}
          unifiedTimezone="UTC"
          loading={false}
          error={null}
          showQuietHours={false}
          setShowQuietHours={() => {}}
          showDigest={true}
          setShowDigest={() => {}}
          onQuietHoursChange={() => {}}
          onDigestChange={() => {}}
          onUnifiedTimezoneChange={() => {}}
        />
      )

      expect(screen.getByText('Enable Daily Digest')).toBeInTheDocument()
      expect(screen.getByText('Digest Time')).toBeInTheDocument()
    })

    test('hides digest content when collapsed', () => {
      render(
        <NotificationPrefsForm
          prefs={defaultPrefs}
          unifiedTimezone="UTC"
          loading={false}
          error={null}
          showQuietHours={false}
          setShowQuietHours={() => {}}
          showDigest={false}
          setShowDigest={() => {}}
          onQuietHoursChange={() => {}}
          onDigestChange={() => {}}
          onUnifiedTimezoneChange={() => {}}
        />
      )

      expect(screen.queryByText('Enable Daily Digest')).not.toBeInTheDocument()
    })
  })

  describe('accessibility', () => {
    test('quiet hours toggle has aria-expanded attribute', () => {
      render(
        <NotificationPrefsForm
          prefs={defaultPrefs}
          unifiedTimezone="UTC"
          loading={false}
          error={null}
          showQuietHours={true}
          setShowQuietHours={() => {}}
          showDigest={false}
          setShowDigest={() => {}}
          onQuietHoursChange={() => {}}
          onDigestChange={() => {}}
          onUnifiedTimezoneChange={() => {}}
        />
      )

      const button = screen.getByText('Quiet Hours').closest('button')
      expect(button).toHaveAttribute('aria-expanded', 'true')
    })

    test('digest toggle has aria-expanded attribute', () => {
      render(
        <NotificationPrefsForm
          prefs={defaultPrefs}
          unifiedTimezone="UTC"
          loading={false}
          error={null}
          showQuietHours={false}
          setShowQuietHours={() => {}}
          showDigest={false}
          setShowDigest={() => {}}
          onQuietHoursChange={() => {}}
          onDigestChange={() => {}}
          onUnifiedTimezoneChange={() => {}}
        />
      )

      const button = screen.getByText('Daily Digest').closest('button')
      expect(button).toHaveAttribute('aria-expanded', 'false')
    })

    test('idPrefix is applied to element IDs', () => {
      render(
        <NotificationPrefsForm
          prefs={defaultPrefs}
          unifiedTimezone="UTC"
          loading={false}
          error={null}
          showQuietHours={true}
          setShowQuietHours={() => {}}
          showDigest={true}
          setShowDigest={() => {}}
          onQuietHoursChange={() => {}}
          onDigestChange={() => {}}
          onUnifiedTimezoneChange={() => {}}
          idPrefix="test"
        />
      )

      expect(screen.getByText('Timezone').closest('label')).toHaveAttribute('for', 'test-unified_timezone')
    })
  })
})
