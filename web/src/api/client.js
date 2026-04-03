const BASE = '/api/v1'

let accessToken = localStorage.getItem('runic_access_token')
let refreshToken = localStorage.getItem('runic_refresh_token')

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
  localStorage.setItem('runic_access_token', access)
  localStorage.setItem('runic_refresh_token', refresh)
}

export function clearTokens() {
  accessToken = null
  refreshToken = null
  localStorage.removeItem('runic_access_token')
  localStorage.removeItem('runic_refresh_token')
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
  try {
    console.log(`[DEBUG] request(${method} ${path}): starting, accessToken=${!!accessToken}, refreshToken=${!!refreshToken}`)
    const fetchOptions = {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    }

    const res = await fetch(BASE + path, fetchOptions)
    console.log(`[DEBUG] request(${method} ${path}): response status=${res.status}, ok=${res.ok}`)

    if (res.status === 401 && retry && refreshToken) {
      console.log(`[DEBUG] request(${method} ${path}): got 401, attempting refresh`)
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
      console.log(`[DEBUG] request(${method} ${path}): not ok, status=${res.status}`)
      const err = await res.json().catch(() => ({ error: res.statusText }))
      const message = typeof err.error === 'string' ? err.error : err.error?.message
      throw new Error(message || 'Request failed')
    }

    if (res.status === 204) return null
    console.log(`[DEBUG] request(${method} ${path}): parsing JSON response`)
    const json = await res.json()
    console.log(`[DEBUG] request(${method} ${path}): parsed, json.data=${!!json.data}, json type=${Array.isArray(json) ? 'array' : typeof json}`)
    return json.data ?? json
  } catch (err) {
    console.error(`[DEBUG] request(${method} ${path}): ERROR: ${err.message}`, err)
    throw err
  }
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

export const getVersion = () => api.get('/info')
