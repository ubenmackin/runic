export const BASE = '/api/v1'

const DEFAULT_TIMEOUT = 30000 // 30 seconds

// Auth failure callback - registered by store to avoid circular imports
let authFailureCallback = null

export function setAuthFailureHandler(fn) {
  authFailureCallback = fn
}

// Read CSRF token from cookie (set by the backend if enabled)
function getCSRFToken() {
  if (typeof document === 'undefined') return ''
  const match = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]*)/)
  return match ? decodeURIComponent(match[1]) : ''
}

// Mutex to prevent multiple concurrent refresh requests
let isRefreshing = false
let refreshPromise = null

async function refreshTokenOnce() {
  if (isRefreshing) {
    // Wait for the existing refresh to complete
    return refreshPromise
  }

  isRefreshing = true
  refreshPromise = fetch(BASE + '/auth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  }).then(res => {
    isRefreshing = false
    return res
  }).catch(err => {
    isRefreshing = false
    throw err
  })

  return refreshPromise
}

async function request(method, path, body, retry = true, signal = null) {
  const headers = { 'Content-Type': 'application/json' }
  const csrfToken = getCSRFToken()
  if (csrfToken) {
    headers['X-CSRF-Token'] = csrfToken
  }

  // Create abort controller with timeout if no signal provided
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT)

  const actualSignal = signal || controller.signal

  const fetchOptions = {
    method,
    headers,
    credentials: 'include',
    body: body ? JSON.stringify(body) : undefined,
    signal: actualSignal,
  }

  try {
    const res = await fetch(BASE + path, fetchOptions)

    if (res.status === 401 && retry) {
      const refreshed = await refreshTokenOnce()
      if (refreshed.ok) {
        clearTimeout(timeoutId)
        return request(method, path, body, false)
      } else {
        if (authFailureCallback) authFailureCallback()
        clearTimeout(timeoutId)
        throw new Error('Session expired. Please log in again.')
      }
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }))
      const message = typeof err.error === 'string' ? err.error : err.error?.message
      const error = new Error(message || 'Request failed')
      error.status = res.status
      error.data = err
      clearTimeout(timeoutId)
      throw error
    }

    clearTimeout(timeoutId)
    if (res.status === 204) return null
    const json = await res.json()
    return json.data ?? json
  } catch (err) {
    clearTimeout(timeoutId)
    if (err.name === 'AbortError') {
      const error = new Error('Request timed out')
      error.status = 408
      throw error
    }
    throw err
  }
}

export const api = {
  get:    (path, signal)        => request('GET',    path, undefined, true, signal),
  post:   (path, body, signal)  => request('POST',   path, body, true, signal),
  put:    (path, body, signal)  => request('PUT',    path, body, true, signal),
  patch:  (path, body, signal)  => request('PATCH',  path, body, true, signal),
  delete: (path, signal)        => request('DELETE', path, undefined, true, signal),
}

export const getAlerts = (params) => api.get(`/alerts?${new URLSearchParams(params)}`)
export const getAlert = (id) => api.get(`/alerts/${id}`)
export const deleteAlert = (id) => api.delete(`/alerts/${id}`)
export const clearAllAlerts = () => api.delete('/alerts')
export const getAlertRules = () => api.get('/alert-rules')
export const updateAlertRule = (id, data) => api.put(`/alert-rules/${id}`, data)

export const getSMTPConfig = () => api.get('/settings/smtp')
export const updateSMTPConfig = (data) => api.put('/settings/smtp', data)
export const testSMTP = () => api.post('/settings/smtp/test')

export const getNotificationPrefs = () => api.get('/users/me/notification-preferences')
export const updateNotificationPrefs = (data) => api.put('/users/me/notification-preferences', data)

export const QUERY_KEYS = {
  peers: () => ['peers'],
  peer: (id) => ['peers', id],
  peerIps: (id) => ['peers', id, 'ips'],
  groups: () => ['groups'],
  group: (id) => ['groups', id],
  members: (id) => ['groups', id, 'members'],
  services: () => ['services'],
  service: (id) => ['services', id],
  policies: () => ['policies'],
  policy: (id) => ['policies', id],
  logs: (params) => ['logs', params],
  alerts: (params) => ['alerts', params],
  alertRules: () => ['alert-rules'],
  smtpConfig: () => ['smtp-config'],
  dashboard: () => ['dashboard'],
  dashboardStats: () => ['dashboard-stats'],
  dashboardInitial: () => ['dashboard-initial'],
  blockedLogs24h: () => ['blocked-logs-24h'],
  setupKeys: () => ['setup-keys'],
  logSettings: () => ['log-settings'],
  notificationPrefs: () => ['notification-preferences'],
  pendingChanges: () => ['pending-changes'],
  importSession: (id) => ['import-session', id],
  importRules: (id) => ['import-rules', id],
  importGroups: (id) => ['import-groups', id],
  importPeers: (id) => ['import-peers', id],
  importServices: (id) => ['import-services', id],
  importSkipped: (id) => ['import-skipped', id],
  info: () => ['info'],
}

export const getVersion = () => api.get('/info')

// Peer lookup by IP
export const getPeerByIP = (ip) => api.get(`/peers/by-ip?ip=${encodeURIComponent(ip)}`)

// Service lookup by port
export const getServiceByPort = (port, protocol = '') => {
  const params = new URLSearchParams({ port })
  if (protocol) params.append('protocol', protocol)
  return api.get(`/services/by-port?${params}`)
}

// Import session API helpers
export const initiateImport = (peerId) => api.post(`/peers/${peerId}/import`)
export const getImportSession = (sessionId) => api.get(`/import-sessions/${sessionId}`)
export const getImportRules = (sessionId) => api.get(`/import-sessions/${sessionId}/rules`)
export const getImportGroups = (sessionId) => api.get(`/import-sessions/${sessionId}/groups`)
export const getImportPeers = (sessionId) => api.get(`/import-sessions/${sessionId}/peers`)
export const getImportServices = (sessionId) => api.get(`/import-sessions/${sessionId}/services`)
export const getImportSkipped = (sessionId) => api.get(`/import-sessions/${sessionId}/skipped`)
export const updateImportRule = (sessionId, ruleId, data) => api.put(`/import-sessions/${sessionId}/rules/${ruleId}`, data)
export const updateImportGroup = (sessionId, groupId, data) => api.put(`/import-sessions/${sessionId}/groups/${groupId}`, data)
export const updateImportPeer = (sessionId, peerId, data) => api.put(`/import-sessions/${sessionId}/peers/${peerId}`, data)
export const updateImportService = (sessionId, serviceId, data) => api.put(`/import-sessions/${sessionId}/services/${serviceId}`, data)
export const applyImport = (sessionId) => api.post(`/import-sessions/${sessionId}/apply`)
export const cancelImport = (sessionId) => api.delete(`/import-sessions/${sessionId}`)

// Peer IP management API helpers
export const getPeerIPs = (peerId) => api.get(`/peers/${peerId}/ips`)
export const addPeerIP = (peerId, ipAddress) => api.post(`/peers/${peerId}/ips`, { ip_address: ipAddress })
export const deletePeerIP = (peerId, ipId) => api.delete(`/peers/${peerId}/ips/${ipId}`)
