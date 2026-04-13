import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

// Mock fetch globally
const originalFetch = global.fetch
let mockFetch

// We need to import the module after setting up mocks
// Store references to be set in beforeEach
let api, setAuthFailureHandler, getAlerts, getAlert, deleteAlert, clearAllAlerts, getAlertRules, updateAlertRule, getSMTPConfig, updateSMTPConfig, testSMTP, getNotificationPrefs, updateNotificationPrefs, getVersion, QUERY_KEYS

describe('API Client', () => {
  beforeEach(async () => {
    // Reset modules to clear internal state (isRefreshing, refreshPromise, authFailureCallback)
    vi.resetModules()
    
    // Set up mock fetch before importing
    mockFetch = vi.fn()
    global.fetch = mockFetch

    // Import fresh module
    const client = await import('./client')
    api = client.api
    setAuthFailureHandler = client.setAuthFailureHandler
    getAlerts = client.getAlerts
    getAlert = client.getAlert
    deleteAlert = client.deleteAlert
    clearAllAlerts = client.clearAllAlerts
    getAlertRules = client.getAlertRules
    updateAlertRule = client.updateAlertRule
    getSMTPConfig = client.getSMTPConfig
    updateSMTPConfig = client.updateSMTPConfig
    testSMTP = client.testSMTP
    getNotificationPrefs = client.getNotificationPrefs
    updateNotificationPrefs = client.updateNotificationPrefs
    getVersion = client.getVersion
    QUERY_KEYS = client.QUERY_KEYS
  })

  afterEach(() => {
    global.fetch = originalFetch
    vi.clearAllMocks()
  })

  describe('request method constructs correct fetch options', () => {
    test('GET request has correct method and headers', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { id: 1 } }),
      })

      await api.get('/test')

      expect(mockFetch).toHaveBeenCalledTimes(1)
      const [url, options] = mockFetch.mock.calls[0]
      expect(url).toBe('/api/v1/test')
      expect(options.method).toBe('GET')
      expect(options.headers).toEqual({ 'Content-Type': 'application/json' })
      expect(options.credentials).toBe('include')
      expect(options.body).toBeUndefined()
    })

    test('POST request includes body when provided', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { id: 1 } }),
      })

      const body = { name: 'test', value: 123 }
      await api.post('/test', body)

      expect(mockFetch).toHaveBeenCalledTimes(1)
      const [url, options] = mockFetch.mock.calls[0]
      expect(url).toBe('/api/v1/test')
      expect(options.method).toBe('POST')
      expect(options.body).toBe(JSON.stringify(body))
    })

    test('PUT request includes body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { id: 1 } }),
      })

      await api.put('/test/1', { name: 'updated' })

      const [, options] = mockFetch.mock.calls[0]
      expect(options.method).toBe('PUT')
      expect(options.body).toBe(JSON.stringify({ name: 'updated' }))
    })

    test('PATCH request includes body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { id: 1 } }),
      })

      await api.patch('/test/1', { name: 'patched' })

      const [, options] = mockFetch.mock.calls[0]
      expect(options.method).toBe('PATCH')
      expect(options.body).toBe(JSON.stringify({ name: 'patched' }))
    })

    test('DELETE request has no body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { success: true } }),
      })

      await api.delete('/test/1')

      const [, options] = mockFetch.mock.calls[0]
      expect(options.method).toBe('DELETE')
      expect(options.body).toBeUndefined()
    })

    test('request without body does not include body in options', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { id: 1 } }),
      })

      await api.get('/test')

      const [, options] = mockFetch.mock.calls[0]
      expect(options.body).toBeUndefined()
    })
  })

  describe('successful responses return parsed JSON', () => {
    test('returns data property from response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { id: 1, name: 'test' } }),
      })

      const result = await api.get('/test')
      expect(result).toEqual({ id: 1, name: 'test' })
    })

    test('returns full response when data property is missing', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ id: 1, name: 'test' }),
      })

      const result = await api.get('/test')
      expect(result).toEqual({ id: 1, name: 'test' })
    })

    test('returns nested data from response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ 
          data: { 
            items: [{ id: 1 }, { id: 2 }],
            total: 2 
          } 
        }),
      })

      const result = await api.get('/items')
      expect(result).toEqual({ 
        items: [{ id: 1 }, { id: 2 }],
        total: 2 
      })
    })

    test('handles array responses', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: [{ id: 1 }, { id: 2 }] }),
      })

      const result = await api.get('/list')
      expect(result).toEqual([{ id: 1 }, { id: 2 }])
    })

    test('handles null data values - returns full response when data is null', async () => {
      // Note: json.data ?? json returns the full json when data is null
      // because ?? returns right side when left is null/undefined
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: null }),
      })

      const result = await api.get('/test')
      expect(result).toEqual({ data: null })
    })
  })

  describe('401 triggers token refresh and retry', () => {
    test('refreshes token on 401 and retries request', async () => {
      // First call returns 401
      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          json: async () => ({ error: 'Unauthorized' }),
        })
        // Refresh call succeeds
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ data: { token: 'new-token' } }),
        })
        // Retry succeeds
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ data: { id: 1, name: 'success' } }),
        })

      const result = await api.get('/protected')

      expect(mockFetch).toHaveBeenCalledTimes(3)
      // First request
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/protected')
      // Refresh request
      expect(mockFetch.mock.calls[1][0]).toBe('/api/v1/auth/refresh')
      expect(mockFetch.mock.calls[1][1].method).toBe('POST')
      // Retry request
      expect(mockFetch.mock.calls[2][0]).toBe('/api/v1/protected')
      
      expect(result).toEqual({ id: 1, name: 'success' })
    })

    test('preserves method and body on retry', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          json: async () => ({ error: 'Unauthorized' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ data: { token: 'new-token' } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ data: { success: true } }),
        })

      const body = { name: 'test' }
      await api.post('/protected', body)

      // Check that retry has the same method and body
      const retryOptions = mockFetch.mock.calls[2][1]
      expect(retryOptions.method).toBe('POST')
      expect(retryOptions.body).toBe(JSON.stringify(body))
    })

test('does not retry more than once (prevents infinite loops)', async () => {
      mockFetch
      // First request returns 401
      .mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: 'Unauthorized' }),
      })
      // Refresh succeeds
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { token: 'new-token' } }),
      })
      // Retry also returns 401 - should not retry again
      .mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: 'Still unauthorized' }),
      })

      await expect(api.get('/protected')).rejects.toThrow('Still unauthorized')
      expect(mockFetch).toHaveBeenCalledTimes(3)
    })

    test('mutex prevents multiple refresh requests', async () => {
      // This test verifies that when multiple requests get 401,
      // they share the same refresh request
      let refreshCallCount = 0

      mockFetch
        // First request returns 401
        .mockImplementationOnce(async () => {
          return {
            ok: false,
            status: 401,
            json: async () => ({ error: 'Unauthorized' }),
          }
        })
        // Second request returns 401
        .mockImplementationOnce(async () => {
          return {
            ok: false,
            status: 401,
            json: async () => ({ error: 'Unauthorized' }),
          }
        })
        // Refresh - track how many times this is called
        .mockImplementationOnce(async () => {
          refreshCallCount++
          return {
            ok: true,
            status: 200,
            json: async () => ({ data: { token: 'new-token' } }),
          }
        })
        // First retry
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ data: { id: 1 } }),
        })
        // Second retry
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ data: { id: 2 } }),
        })

      // Make two concurrent requests
      const [result1, result2] = await Promise.all([
        api.get('/protected1'),
        api.get('/protected2'),
      ])

      // Both requests should succeed
      expect(result1).toEqual({ id: 1 })
      expect(result2).toEqual({ id: 2 })
      
      // Refresh should only be called once
      expect(refreshCallCount).toBe(1)
    })
  })

describe('failed refresh calls authFailureCallback', () => {
    test('calls authFailureCallback when refresh fails', async () => {
      const callback = vi.fn()
      setAuthFailureHandler(callback)

      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          json: async () => ({ error: 'Unauthorized' }),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          json: async () => ({ error: 'Session expired' }),
        })

      await expect(api.get('/protected')).rejects.toThrow('Session expired. Please log in again.')
      expect(callback).toHaveBeenCalledTimes(1)
    })

    test('throws error when refresh returns non-ok status', async () => {
      const callback = vi.fn()
      setAuthFailureHandler(callback)

      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          json: async () => ({ error: 'Unauthorized' }),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 403,
          json: async () => ({ error: 'Forbidden' }),
        })

      await expect(api.get('/protected')).rejects.toThrow('Session expired. Please log in again.')
      expect(callback).toHaveBeenCalledTimes(1)
    })

    test('handles missing authFailureCallback gracefully', async () => {
      // Don't set a callback - authFailureCallback is null by default in fresh module
      
      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          json: async () => ({ error: 'Unauthorized' }),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          json: async () => ({ error: 'Session expired' }),
        })

      // Should still throw, just not call any callback
      await expect(api.get('/protected')).rejects.toThrow('Session expired. Please log in again.')
    })
  })

  describe('204 responses return null', () => {
    test('204 No Content returns null', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 204,
      })

      const result = await api.delete('/test/1')
      expect(result).toBeNull()
    })

    test('204 does not try to parse JSON', async () => {
      const jsonSpy = vi.fn()
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 204,
        json: jsonSpy,
      })

      const result = await api.delete('/test/1')
      expect(result).toBeNull()
      expect(jsonSpy).not.toHaveBeenCalled()
    })

    test('204 from PUT request returns null', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 204,
      })

      const result = await api.put('/test/1', { name: 'updated' })
      expect(result).toBeNull()
    })
  })

  describe('error responses throw with proper message', () => {
    test('throws error with message from error field', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: async () => ({ error: 'Invalid input provided' }),
      })

      await expect(api.post('/test', {})).rejects.toThrow('Invalid input provided')
    })

    test('throws error with message from nested error.message', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 422,
        statusText: 'Unprocessable Entity',
        json: async () => ({ error: { message: 'Validation failed' } }),
      })

      await expect(api.post('/test', {})).rejects.toThrow('Validation failed')
    })

    test('includes status code on error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        json: async () => ({ error: 'Resource not found' }),
      })

      try {
        await api.get('/test/999')
      } catch (error) {
        expect(error.status).toBe(404)
        expect(error.message).toBe('Resource not found')
      }
    })

    test('includes error data on error object', async () => {
      const errorData = { error: 'Conflict', details: 'Item already exists' }
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 409,
        statusText: 'Conflict',
        json: async () => errorData,
      })

      try {
        await api.post('/test', {})
      } catch (error) {
        expect(error.data).toEqual(errorData)
      }
    })

    test('uses statusText when JSON parse fails', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: async () => { throw new Error('Invalid JSON') },
      })

      await expect(api.get('/test')).rejects.toThrow('Internal Server Error')
    })

    test('handles error response without error field', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: async () => ({ message: 'Something went wrong' }),
      })

      await expect(api.get('/test')).rejects.toThrow('Request failed')
    })

    test('handles non-string error field', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: async () => ({ error: { code: 'INVALID', details: 'Invalid input' } }),
      })

      await expect(api.post('/test', {})).rejects.toThrow('Request failed')
    })

    test('handles empty error message', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: async () => ({ error: '' }),
      })

      await expect(api.post('/test', {})).rejects.toThrow('Request failed')
    })
  })

  describe('all HTTP methods work correctly', () => {
    const mockSuccessResponse = { data: { success: true } }

    test('GET method works', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockSuccessResponse,
      })

      const result = await api.get('/resource')
      expect(result).toEqual({ success: true })
      expect(mockFetch.mock.calls[0][1].method).toBe('GET')
    })

    test('POST method works', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => ({ data: { id: 1, created: true } }),
      })

      const result = await api.post('/resource', { name: 'new' })
      expect(result).toEqual({ id: 1, created: true })
      expect(mockFetch.mock.calls[0][1].method).toBe('POST')
    })

    test('PUT method works', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { id: 1, updated: true } }),
      })

      const result = await api.put('/resource/1', { name: 'updated' })
      expect(result).toEqual({ id: 1, updated: true })
      expect(mockFetch.mock.calls[0][1].method).toBe('PUT')
    })

    test('PATCH method works', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { id: 1, patched: true } }),
      })

      const result = await api.patch('/resource/1', { name: 'patched' })
      expect(result).toEqual({ id: 1, patched: true })
      expect(mockFetch.mock.calls[0][1].method).toBe('PATCH')
    })

    test('DELETE method works', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { deleted: true } }),
      })

      const result = await api.delete('/resource/1')
      expect(result).toEqual({ deleted: true })
      expect(mockFetch.mock.calls[0][1].method).toBe('DELETE')
    })
  })

  describe('helper functions', () => {
    test('getAlerts constructs correct URL with params', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: [] }),
      })

      await getAlerts({ status: 'active', limit: 10 })
      expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/alerts?')
      expect(mockFetch.mock.calls[0][0]).toContain('status=active')
      expect(mockFetch.mock.calls[0][0]).toContain('limit=10')
    })

    test('getAlert constructs correct URL', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { id: 'alert-1' } }),
      })

      await getAlert('alert-1')
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/alerts/alert-1')
    })

    test('deleteAlert constructs correct URL', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 204,
      })

      await deleteAlert('alert-1')
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/alerts/alert-1')
      expect(mockFetch.mock.calls[0][1].method).toBe('DELETE')
    })

    test('clearAllAlerts calls correct endpoint', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 204,
      })

      await clearAllAlerts()
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/alerts')
      expect(mockFetch.mock.calls[0][1].method).toBe('DELETE')
    })

    test('getAlertRules calls correct endpoint', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: [] }),
      })

      await getAlertRules()
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/alert-rules')
    })

    test('updateAlertRule constructs correct URL and method', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { id: 'rule-1' } }),
      })

      await updateAlertRule('rule-1', { enabled: true })
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/alert-rules/rule-1')
      expect(mockFetch.mock.calls[0][1].method).toBe('PUT')
    })

    test('getSMTPConfig calls correct endpoint', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { host: 'smtp.example.com' } }),
      })

      await getSMTPConfig()
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/settings/smtp')
    })

    test('updateSMTPConfig sends PUT request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { success: true } }),
      })

      await updateSMTPConfig({ host: 'smtp.example.com' })
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/settings/smtp')
      expect(mockFetch.mock.calls[0][1].method).toBe('PUT')
    })

    test('testSMTP sends POST request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { success: true } }),
      })

      await testSMTP()
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/settings/smtp/test')
      expect(mockFetch.mock.calls[0][1].method).toBe('POST')
    })

    test('getNotificationPrefs calls correct endpoint', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { email: true } }),
      })

      await getNotificationPrefs()
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/users/me/notification-preferences')
    })

    test('updateNotificationPrefs sends PUT request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { success: true } }),
      })

      await updateNotificationPrefs({ email: false })
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/users/me/notification-preferences')
      expect(mockFetch.mock.calls[0][1].method).toBe('PUT')
    })

    test('getVersion calls correct endpoint', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { version: '1.0.0' } }),
      })

      await getVersion()
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/info')
    })
  })

  describe('QUERY_KEYS constants', () => {
    test('QUERY_KEYS.peers returns correct key', () => {
      expect(QUERY_KEYS.peers()).toEqual(['peers'])
    })

    test('QUERY_KEYS.peer returns correct key with id', () => {
      expect(QUERY_KEYS.peer('peer-1')).toEqual(['peers', 'peer-1'])
    })

    test('QUERY_KEYS.groups returns correct key', () => {
      expect(QUERY_KEYS.groups()).toEqual(['groups'])
    })

    test('QUERY_KEYS.group returns correct key with id', () => {
      expect(QUERY_KEYS.group('group-1')).toEqual(['groups', 'group-1'])
    })

    test('QUERY_KEYS.members returns correct nested key', () => {
      expect(QUERY_KEYS.members('group-1')).toEqual(['groups', 'group-1', 'members'])
    })

    test('QUERY_KEYS.services returns correct key', () => {
      expect(QUERY_KEYS.services()).toEqual(['services'])
    })

    test('QUERY_KEYS.policies returns correct key', () => {
      expect(QUERY_KEYS.policies()).toEqual(['policies'])
    })

    test('QUERY_KEYS.logs returns correct key with params', () => {
      expect(QUERY_KEYS.logs({ limit: 100 })).toEqual(['logs', { limit: 100 }])
    })

    test('QUERY_KEYS.alerts returns correct key with params', () => {
      expect(QUERY_KEYS.alerts({ status: 'active' })).toEqual(['alerts', { status: 'active' }])
    })

    test('QUERY_KEYS.dashboard returns correct key', () => {
      expect(QUERY_KEYS.dashboard()).toEqual(['dashboard'])
    })
  })

  describe('edge cases', () => {
    test('handles network errors', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'))

      await expect(api.get('/test')).rejects.toThrow('Network error')
    })

    test('handles timeout errors', async () => {
      mockFetch.mockRejectedValueOnce(new Error('The operation was aborted due to timeout'))

      await expect(api.get('/test')).rejects.toThrow('timeout')
    })

    test('handles empty object response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({}),
      })

      const result = await api.get('/test')
      expect(result).toEqual({})
    })

    test('handles string response in data field', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: 'simple string' }),
      })

      const result = await api.get('/test')
      expect(result).toBe('simple string')
    })

    test('handles boolean response in data field', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: true }),
      })

      const result = await api.get('/test')
      expect(result).toBe(true)
    })

    test('handles number response in data field', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: 42 }),
      })

      const result = await api.get('/test')
      expect(result).toBe(42)
    })

    test('handles null body in POST request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { success: true } }),
      })

      await api.post('/test', null)
      const [, options] = mockFetch.mock.calls[0]
      expect(options.body).toBeUndefined()
    })

    test('handles undefined body in POST request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { success: true } }),
      })

      await api.post('/test', undefined)
      const [, options] = mockFetch.mock.calls[0]
      expect(options.body).toBeUndefined()
    })

    test('encodes path correctly', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: null }),
      })

      await api.get('/test%20path')
      expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/test%20path')
    })
  })
})
