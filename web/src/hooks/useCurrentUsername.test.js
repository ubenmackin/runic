import { renderHook } from '@testing-library/react'
import { describe, test, expect, beforeEach, afterEach } from 'vitest'
import { useCurrentUsername, buildStorageKey } from './useCurrentUsername'
import { useAuthStore } from '../store'

describe('useCurrentUsername', () => {
  const originalState = useAuthStore.getState()

  beforeEach(() => {
    useAuthStore.setState({
      isAuthenticated: null,
      username: null,
      role: null,
    })
  })

  afterEach(() => {
    useAuthStore.setState(originalState)
  })

  test('returns null when not authenticated', () => {
    useAuthStore.setState({ username: null, isAuthenticated: false })
    const { result } = renderHook(() => useCurrentUsername())
    expect(result.current).toBe(null)
  })

  test('returns username when authenticated', () => {
    useAuthStore.setState({ username: 'testuser', isAuthenticated: true })
    const { result } = renderHook(() => useCurrentUsername())
    expect(result.current).toBe('testuser')
  })

  test('returns null when auth is pending', () => {
    useAuthStore.setState({ username: null, isAuthenticated: null })
    const { result } = renderHook(() => useCurrentUsername())
    expect(result.current).toBe(null)
  })
})

describe('buildStorageKey', () => {
  test('returns namespaced key when username is provided', () => {
    expect(buildStorageKey('admin', 'peers', 'filter')).toBe('runic_admin_peers_filter')
  })

  test('returns null when username is null', () => {
    expect(buildStorageKey(null, 'peers', 'filter')).toBe(null)
  })

  test('returns null when username is empty string', () => {
    expect(buildStorageKey('', 'peers', 'filter')).toBe(null)
  })

  test('handles different page and setting keys', () => {
    expect(buildStorageKey('user1', 'policies', 'sort')).toBe('runic_user1_policies_sort')
    expect(buildStorageKey('user1', 'logs', 'rowsPerPage')).toBe('runic_user1_logs_rowsPerPage')
  })
})
