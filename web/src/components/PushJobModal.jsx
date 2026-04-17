import { useState, useEffect, useRef, useCallback } from 'react'
import ReactDOM from 'react-dom'
import { X, CheckCircle, AlertCircle, Loader2 } from 'lucide-react'

export default function PushJobModal({ jobId, onClose }) {
  const [jobStatus, setJobStatus] = useState('connecting') // connecting, running, completed, completed_with_errors, failed
  const [total, setTotal] = useState(0)
  const [succeeded, setSucceeded] = useState(0)
  const [failed, setFailed] = useState(0)
  const [peers, setPeers] = useState({}) // peer_id -> { hostname, status, error }
  const eventSourceRef = useRef(null)
  const autoCloseTimerRef = useRef(null)

  const handleClose = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
    }
    if (autoCloseTimerRef.current) {
      clearTimeout(autoCloseTimerRef.current)
    }
    onClose()
  }, [onClose])

  useEffect(() => {
    if (!jobId) return

    const es = new EventSource(`/api/v1/push-jobs/${jobId}/events`)
    eventSourceRef.current = es

    es.addEventListener('init', (e) => {
      try {
        const data = JSON.parse(e.data)
        setTotal(data.total || 0)
        setSucceeded(data.succeeded || 0)
        setFailed(data.failed || 0)
        setJobStatus(data.status === 'running' ? 'running' : data.status || 'connecting')
        if (data.peers && Array.isArray(data.peers)) {
          const peerMap = {}
          data.peers.forEach(p => {
            peerMap[p.peer_id] = { hostname: p.peer_hostname || p.hostname, status: p.status, error: p.error_message }
          })
          setPeers(peerMap)
        }
      } catch (err) {
        console.error('Failed to parse init event:', err)
      }
    })

    es.addEventListener('progress', (e) => {
      try {
        const data = JSON.parse(e.data)
        setTotal(data.total || 0)
        setSucceeded(data.succeeded || 0)
        setFailed(data.failed || 0)
        if (data.peer_id) {
          setPeers(prev => ({
            ...prev,
            [data.peer_id]: { hostname: data.hostname, status: 'processing', error: null }
          }))
        }
      } catch (err) {
        console.error('Failed to parse progress event:', err)
      }
    })

    es.addEventListener('peer_success', (e) => {
      try {
        const data = JSON.parse(e.data)
        setSucceeded(data.succeeded || 0)
        setFailed(data.failed || 0)
        setTotal(data.total || 0)
        setPeers(prev => ({
          ...prev,
          [data.peer_id]: { hostname: data.hostname, status: 'notified', error: null }
        }))
      } catch (err) {
        console.error('Failed to parse peer_success event:', err)
      }
    })

    es.addEventListener('peer_failed', (e) => {
      try {
        const data = JSON.parse(e.data)
        setSucceeded(data.succeeded || 0)
        setFailed(data.failed || 0)
        setTotal(data.total || 0)
        setPeers(prev => ({
          ...prev,
          [data.peer_id]: { hostname: data.hostname, status: 'failed', error: data.error }
        }))
      } catch (err) {
        console.error('Failed to parse peer_failed event:', err)
      }
    })

    es.addEventListener('complete', (e) => {
      try {
        const data = JSON.parse(e.data)
        setJobStatus(data.status || 'completed')
        setSucceeded(data.succeeded || 0)
        setFailed(data.failed || 0)
        setTotal(data.total || 0)
        // Auto-close after 3 seconds
        const timer = setTimeout(() => {
          handleClose()
        }, 3000)
        autoCloseTimerRef.current = timer
      } catch (err) {
        console.error('Failed to parse complete event:', err)
      }
    })

    es.onerror = () => {
      // SSE auto-reconnects; only log if connection is permanently closed
      if (es.readyState === EventSource.CLOSED) {
        console.log('SSE connection closed for job', jobId)
      }
      // Otherwise, EventSource is reconnecting automatically — no action needed
    }

    return () => {
      es.close()
      if (autoCloseTimerRef.current) {
        clearTimeout(autoCloseTimerRef.current)
      }
    }
  }, [jobId, handleClose])

  const percentage = total > 0 ? Math.round(((succeeded + failed) / total) * 100) : 0
  const isComplete = jobStatus === 'completed' || jobStatus === 'completed_with_errors' || jobStatus === 'failed'

  const getStatusIcon = (status) => {
    switch (status) {
      case 'notified':
      case 'applied':
        return <CheckCircle className="w-4 h-4 text-green-500" />
      case 'failed':
        return <AlertCircle className="w-4 h-4 text-red-500" />
      case 'processing':
        return <Loader2 className="w-4 h-4 text-blue-500 animate-spin" />
      case 'pending':
        return <Loader2 className="w-4 h-4 text-gray-400 animate-spin" />
      default:
        return <Loader2 className="w-4 h-4 text-gray-400 animate-spin" />
    }
  }

  const peerList = Object.entries(peers).sort(([, a], [, b]) => (a.hostname || '').localeCompare(b.hostname || ''))

  const modalContent = (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50">
      <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none w-full max-w-lg mx-4 max-h-[80vh] flex flex-col overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-border">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">
            Pushing Rules to All Peers
          </h2>
          <button
            onClick={handleClose}
            className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-4 overflow-y-auto flex-1">
          <div className="mb-4">
            <div className="flex justify-between text-sm text-gray-600 dark:text-gray-400 mb-1">
              <span>{succeeded + failed} of {total} peers</span>
              <span>{percentage}%</span>
            </div>
<div className="w-full bg-gray-200 dark:bg-charcoal-darkest rounded-none h-2.5">
								<div
									className={`h-2.5 rounded-none transition-all duration-300 ${
                  isComplete && failed > 0
                    ? 'bg-amber-500'
                    : isComplete && failed === 0
                    ? 'bg-green-500'
                    : 'bg-blue-500'
                }`}
                style={{ width: `${percentage}%` }}
              />
            </div>
          </div>

          <div className="flex gap-4 mb-4 text-sm">
            <div className="flex items-center gap-1.5">
              <CheckCircle className="w-4 h-4 text-green-500" />
              <span className="text-green-600 dark:text-green-400">{succeeded} succeeded</span>
            </div>
            {failed > 0 && (
              <div className="flex items-center gap-1.5">
                <AlertCircle className="w-4 h-4 text-red-500" />
                <span className="text-red-600 dark:text-red-400">{failed} failed</span>
              </div>
            )}
            {!isComplete && (
              <div className="flex items-center gap-1.5">
                <Loader2 className="w-4 h-4 text-blue-500 animate-spin" />
                <span className="text-blue-600 dark:text-blue-400">In progress...</span>
              </div>
            )}
          </div>

          {peerList.length > 0 && (
            <div className="space-y-1">
              <h3 className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-2">
                Peer Status
              </h3>
              {peerList.map(([peerId, peer]) => (
                <div
                  key={peerId}
                  className="flex items-center justify-between py-1.5 px-2 rounded-none bg-gray-50 dark:bg-charcoal-darkest"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    {getStatusIcon(peer.status)}
                    <span className="text-sm text-gray-700 dark:text-gray-300 truncate">
                      {peer.hostname || 'Unknown'}
                    </span>
                  </div>
                  {peer.error && (
                    <span className="text-xs text-red-500 truncate max-w-[150px]" title={peer.error}>
                      {peer.error.substring(0, 50)}{peer.error.length > 50 ? '...' : ''}
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="flex justify-end gap-3 p-4 border-t border-gray-200 dark:border-gray-border bg-gray-50 dark:bg-charcoal-darkest">
          <button
            onClick={handleClose}
            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-none hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
          >
            {isComplete ? 'Close' : 'Close & Run in Background'}
          </button>
        </div>
      </div>
    </div>
  )

  return ReactDOM.createPortal(modalContent, document.body)
}
