const BASE = '/api/v1'

let accessToken = sessionStorage.getItem('runic_access_token')
let refreshToken = sessionStorage.getItem('runic_refresh_token')

// Auth failure callback - registered by store to avoid circular imports
let authFailureCallback = null

export function setAuthFailureHandler(fn) {
  authFailureCallback = fn
}

// Mutex to prevent multiple concurrent refresh requests
let isRefreshing = false
let refreshPromise = null

export function setTokens(access, refresh) {
  accessToken = access
  refreshToken = refresh
  sessionStorage.setItem('runic_access_token', access)
  sessionStorage.setItem('runic_refresh_token', refresh)
}

export function clearTokens() {
  accessToken = null
  refreshToken = null
  sessionStorage.removeItem('runic_access_token')
  sessionStorage.removeItem('runic_refresh_token')
}

export function getAccessToken() {
  return accessToken
}

async function refreshTokenOnce() {
  if (isRefreshing) {
    // Wait for the existing refresh to complete
    return refreshPromise
  }
  
  isRefreshing = true
  refreshPromise = fetch(BASE + '/auth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
  }).then(res => {
    isRefreshing = false
    return res
  }).catch(err => {
    isRefreshing = false
    throw err
  })
  
  return refreshPromise
}

async function request(method, path, body, retry = true) {
  const res = await fetch(BASE + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  })

  if (res.status === 401 && retry && refreshToken) {
    const refreshed = await refreshTokenOnce()
    if (refreshed.ok) {
      const data = await refreshed.json()
      setTokens(data.access_token, data.refresh_token)
      return request(method, path, body, false)
    } else {
      clearTokens()
      if (authFailureCallback) authFailureCallback()
      throw new Error('Session expired. Please log in again.')
    }
  }

	if (!res.ok) {
		const err = await res.json().catch(() => ({ error: res.statusText }))
		// Handle both { error: "message" } and { error: { message: "..." } } formats
		const message = typeof err.error === 'string' ? err.error : err.error?.message
		throw new Error(message || 'Request failed')
	}

  if (res.status === 204) return null
  const json = await res.json()
  return json.data ?? json
}

export const api = {
  get:    (path)        => request('GET',    path),
  post:   (path, body)  => request('POST',   path, body),
  put:    (path, body)  => request('PUT',    path, body),
  patch:  (path, body)  => request('PATCH',  path, body),
  delete: (path)        => request('DELETE', path),
}

export const QUERY_KEYS = {
  peers: () => ['peers'],
  peer: (id) => ['peers', id],
  groups: () => ['groups'],
  group: (id) => ['groups', id],
  members: (id) => ['groups', id, 'members'],
  services: () => ['services'],
  service: (id) => ['services', id],
  policies: () => ['policies'],
  policy: (id) => ['policies', id],
  logs: (params) => ['logs', params],
  dashboard: () => ['dashboard'],
  dashboardInitial: () => ['dashboard-initial'],
  blockedLogs24h: () => ['blocked-logs-24h'],
}
