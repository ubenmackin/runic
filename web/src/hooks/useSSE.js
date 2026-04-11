/**
 * useSSE - React hook for Server-Sent Events (SSE) connections
 * 
 * Provides real-time notifications from the backend via SSE.
 * Automatically reconnects on connection failure.
 */
import { useEffect, useRef, useCallback } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { QUERY_KEYS } from '../api/client'

/**
 * Hook for connecting to the frontend SSE endpoint
 * 
 * @param {Object} options - Hook options
 * @param {boolean} options.enabled - Whether to connect (default: true)
 * @param {Function} options.onPendingChangeAdded - Callback when pending_change_added event received
 * @returns {Object} - { connected, error }
 */
export function useSSE({ enabled = true, onPendingChangeAdded } = {}) {
  const queryClient = useQueryClient()
  const eventSourceRef = useRef(null)
  const reconnectTimeoutRef = useRef(null)
  const reconnectAttemptsRef = useRef(0)
  const mountedRef = useRef(true)

  const connect = useCallback(() => {
    if (!enabled || !mountedRef.current) return

    // Close existing connection if any
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
    }

    const es = new EventSource('/api/v1/events', {
      withCredentials: true,
    })
    eventSourceRef.current = es

    es.addEventListener('connected', () => {
      // Reset reconnect attempts on successful connection
      reconnectAttemptsRef.current = 0
    })

    es.addEventListener('pending_change_added', (e) => {
      try {
        const data = JSON.parse(e.data)
        const peerId = data.peer_id

		// Invalidate relevant queries to refresh the UI
		queryClient.invalidateQueries({ queryKey: QUERY_KEYS.peers() })
		queryClient.invalidateQueries({ queryKey: QUERY_KEYS.pendingChanges() })

        // Call custom handler if provided
        if (onPendingChangeAdded) {
          onPendingChangeAdded(peerId, data)
        }
      } catch (err) {
        console.error('Failed to parse pending_change_added event:', err)
      }
    })

    es.onerror = (err) => {
      if (es.readyState === EventSource.CLOSED) {
        console.log('SSE connection closed')
        
        // Attempt to reconnect with exponential backoff
        if (mountedRef.current && enabled) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttemptsRef.current), 30000)
          reconnectAttemptsRef.current++
          
          console.log(`SSE reconnecting in ${delay}ms (attempt ${reconnectAttemptsRef.current})`)
          
          reconnectTimeoutRef.current = setTimeout(() => {
            if (mountedRef.current && enabled) {
              connect()
            }
          }, delay)
        }
      }
    }
  }, [enabled, queryClient, onPendingChangeAdded])

  useEffect(() => {
    mountedRef.current = true

    if (enabled) {
      connect()
    }

    return () => {
      mountedRef.current = false
      
      if (eventSourceRef.current) {
        eventSourceRef.current.close()
        eventSourceRef.current = null
      }
      
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
        reconnectTimeoutRef.current = null
      }
    }
  }, [enabled, connect])

  return {
    connected: eventSourceRef.current?.readyState === EventSource.OPEN,
  }
}

export default useSSE
