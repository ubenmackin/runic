import { renderHook } from '@testing-library/react'
import { describe, test, expect, beforeEach, afterEach } from 'vitest'
import { useAuth } from './useAuth'
import { useAuthStore } from '../store'

describe('useAuth', () => {
  // Reset the store state before each test
  const originalState = useAuthStore.getState()

  beforeEach(() => {
    // Reset to initial state before each test
    useAuthStore.setState({
      isAuthenticated: null,
      username: null,
      role: null,
    })
  })

  afterEach(() => {
    // Restore original state after each test
    useAuthStore.setState(originalState)
  })

  describe('returns user object when authenticated', () => {
    test('returns correct role when user is authenticated', () => {
      useAuthStore.setState({
        isAuthenticated: true,
        username: 'testuser',
        role: 'admin',
      })

      const { result } = renderHook(() => useAuth())

      expect(result.current.role).toBe('admin')
      expect(result.current.isAdmin).toBe(true)
      expect(result.current.isEditor).toBe(true)
      expect(result.current.canEdit).toBe(true)
    })

    test('returns correct values for editor role', () => {
      useAuthStore.setState({
        isAuthenticated: true,
        username: 'editoruser',
        role: 'editor',
      })

      const { result } = renderHook(() => useAuth())

      expect(result.current.role).toBe('editor')
      expect(result.current.isAdmin).toBe(false)
      expect(result.current.isEditor).toBe(true)
      expect(result.current.canEdit).toBe(true)
    })

    test('returns correct values for viewer role', () => {
      useAuthStore.setState({
        isAuthenticated: true,
        username: 'vieweruser',
        role: 'viewer',
      })

      const { result } = renderHook(() => useAuth())

      expect(result.current.role).toBe('viewer')
      expect(result.current.isAdmin).toBe(false)
      expect(result.current.isEditor).toBe(false)
      expect(result.current.canEdit).toBe(false)
    })
  })

  describe('returns null when not authenticated', () => {
    test('returns null role when not authenticated', () => {
      useAuthStore.setState({
        isAuthenticated: false,
        username: null,
        role: null,
      })

      const { result } = renderHook(() => useAuth())

      expect(result.current.role).toBe(null)
      expect(result.current.isAdmin).toBe(false)
      expect(result.current.isEditor).toBe(false)
      expect(result.current.canEdit).toBe(false)
    })

    test('returns null role when authentication is pending', () => {
      useAuthStore.setState({
        isAuthenticated: null,
        username: null,
        role: null,
      })

      const { result } = renderHook(() => useAuth())

      expect(result.current.role).toBe(null)
      expect(result.current.isAdmin).toBe(false)
      expect(result.current.isEditor).toBe(false)
      expect(result.current.canEdit).toBe(false)
    })
  })

  describe('isAdmin/isEditor computed correctly', () => {
    test('isAdmin is true only for admin role', () => {
      // Test admin
      useAuthStore.setState({ role: 'admin' })
      const { result: adminResult } = renderHook(() => useAuth())
      expect(adminResult.current.isAdmin).toBe(true)

      // Test editor
      useAuthStore.setState({ role: 'editor' })
      const { result: editorResult } = renderHook(() => useAuth())
      expect(editorResult.current.isAdmin).toBe(false)

      // Test viewer
      useAuthStore.setState({ role: 'viewer' })
      const { result: viewerResult } = renderHook(() => useAuth())
      expect(viewerResult.current.isAdmin).toBe(false)
    })

    test('isEditor is true for admin and editor roles', () => {
      // Test admin
      useAuthStore.setState({ role: 'admin' })
      const { result: adminResult } = renderHook(() => useAuth())
      expect(adminResult.current.isEditor).toBe(true)

      // Test editor
      useAuthStore.setState({ role: 'editor' })
      const { result: editorResult } = renderHook(() => useAuth())
      expect(editorResult.current.isEditor).toBe(true)

      // Test viewer
      useAuthStore.setState({ role: 'viewer' })
      const { result: viewerResult } = renderHook(() => useAuth())
      expect(viewerResult.current.isEditor).toBe(false)
    })

    test('canEdit matches isEditor behavior', () => {
      // Test admin
      useAuthStore.setState({ role: 'admin' })
      const { result: adminResult } = renderHook(() => useAuth())
      expect(adminResult.current.canEdit).toBe(true)

      // Test editor
      useAuthStore.setState({ role: 'editor' })
      const { result: editorResult } = renderHook(() => useAuth())
      expect(editorResult.current.canEdit).toBe(true)

      // Test viewer
      useAuthStore.setState({ role: 'viewer' })
      const { result: viewerResult } = renderHook(() => useAuth())
      expect(viewerResult.current.canEdit).toBe(false)
    })
  })
})
