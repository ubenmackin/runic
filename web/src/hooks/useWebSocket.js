import { useEffect, useRef, useCallback, useState } from 'react'
import { logger } from '../utils/logger'

/**
 * Hook for WebSocket connections with exponential backoff reconnection.
 *
 * @param {Object} options
 * @param {string} options.url - WebSocket URL
 * @param {boolean} [options.enabled=true] - Whether to connect
 * @param {number} [options.maxRetries=10] - Maximum reconnection attempts
 * @param {number} [options.baseDelay=1000] - Base delay for exponential backoff (ms)
 * @param {number} [options.maxDelay=30000] - Maximum delay between retries (ms)
 * @param {Function} [options.onMessage] - Callback for incoming messages
 * @param {Function} [options.onOpen] - Callback when connection opens
 * @returns {{ connected: boolean, error: Error|null, retryCount: number }}
 */
export function useWebSocket({ url, enabled = true, maxRetries = 10, baseDelay = 1000, maxDelay = 30000, onMessage, onOpen }) {
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState(null)
  const [retryCount, setRetryCount] = useState(0)
  const wsRef = useRef(null)
  const retryCountRef = useRef(0)
  const retryTimeoutRef = useRef(null)
  const mountedRef = useRef(true)
  const onMessageRef = useRef(onMessage)
  const onOpenRef = useRef(onOpen)
  const connectRef = useRef(null)

  useEffect(() => {
    onMessageRef.current = onMessage
  }, [onMessage])

  useEffect(() => {
    onOpenRef.current = onOpen
  }, [onOpen])

  const connect = useCallback(() => {
    if (!enabled || !mountedRef.current) return

    // Clean up existing connection
    if (wsRef.current) {
      wsRef.current.onclose = null
      wsRef.current.onerror = null
      wsRef.current.onopen = null
      wsRef.current.onmessage = null
      wsRef.current.close()
      wsRef.current = null
    }

    try {
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        if (!mountedRef.current) return
        retryCountRef.current = 0
        setRetryCount(0)
        setConnected(true)
        setError(null)
        onOpenRef.current?.()
      }

      ws.onmessage = (event) => {
        if (!mountedRef.current) return
        onMessageRef.current?.(event)
      }

      ws.onclose = () => {
        if (!mountedRef.current) return
        setConnected(false)
        // Schedule reconnection with exponential backoff
        if (retryCountRef.current < maxRetries) {
          const delay = Math.min(baseDelay * Math.pow(2, retryCountRef.current), maxDelay)
          retryCountRef.current++
          setRetryCount(retryCountRef.current)
          retryTimeoutRef.current = setTimeout(() => {
            if (mountedRef.current && enabled && connectRef.current) {
              connectRef.current()
            }
          }, delay)
        } else {
          setError(new Error('WebSocket connection failed: max retries reached'))
        }
      }

      ws.onerror = (event) => {
        logger.error('WebSocket error:', event)
        // onclose will handle reconnection
      }
    } catch (err) {
      if (mountedRef.current) {
        setError(err)
      }
    }
  }, [url, enabled, maxRetries, baseDelay, maxDelay])

  // Store connect in a ref so the timeout closure can use it without circular deps
  useEffect(() => {
    connectRef.current = connect
  }, [connect])

  useEffect(() => {
    mountedRef.current = true

    if (enabled) {
      connect()
    }

    return () => {
      mountedRef.current = false
      if (wsRef.current) {
        wsRef.current.close()
      }
      if (retryTimeoutRef.current) {
        clearTimeout(retryTimeoutRef.current)
      }
    }
  }, [enabled, connect])

  return { connected, error, retryCount }
}

export default useWebSocket