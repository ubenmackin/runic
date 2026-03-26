import { useState, useEffect, useRef, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { FileText, RefreshCw, Play, Pause, Trash2, Wifi, WifiOff } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useDebounce } from '../hooks/useDebounce'
import EmptyState from '../components/EmptyState'
import TableSkeleton from '../components/TableSkeleton'
import LogLine from '../components/LogLine'

export default function Logs() {
  const [mode, setMode] = useState('historical') // 'live' | 'historical'
  const [filter, setFilter] = useState({
    server_id: '',
    action: '',
    src_ip: '',
    dst_port: '',
    from: '',
    to: '',
    limit: 100,
    offset: 0,
  })

  // Debounce filter for query
  const debouncedFilter = useDebounce(filter)

  // Live mode state
  const [liveLogs, setLiveLogs] = useState([])
  const [isConnected, setIsConnected] = useState(false)
  const [isPaused, setIsPaused] = useState(false)
  const wsRef = useRef(null)
  const logsEndRef = useRef(null)
  const isPausedRef = useRef(false)
  const MAX_LIVE_LOGS = 500

  // Historical query
  const { data, isLoading, refetch } = useQuery({
    queryKey: QUERY_KEYS.logs(debouncedFilter),
    queryFn: () => api.get(`/logs?${new URLSearchParams(
      Object.entries(debouncedFilter).filter(([_, v]) => v !== '').map(([k, v]) => [k, String(v)])
    )}`),
    enabled: mode === 'historical',
    refetchInterval: mode === 'historical' ? false : false,
  })

// Peers for filter dropdown
const { data: peers } = useQuery({
  queryKey: QUERY_KEYS.peers,
  queryFn: () => api.get('/peers'),
})

  // WebSocket connection for live mode
  useEffect(() => {
    if (mode !== 'live') {
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }
      setIsConnected(false)
      return
    }

    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const token = sessionStorage.getItem('runic_access_token')
    const wsUrl = `${wsProto}//${window.location.host}/api/v1/logs/stream?token=${encodeURIComponent(token || '')}`
    const ws = new WebSocket(wsUrl)

    ws.onopen = () => {
      setIsConnected(true)
      console.log('WebSocket connected')
    }

    ws.onmessage = (event) => {
      if (isPausedRef.current) return
      try {
        const log = JSON.parse(event.data)
        setLiveLogs(prev => {
          const newLogs = [log, ...prev].slice(0, MAX_LIVE_LOGS)
          return newLogs
        })
      } catch (e) {
        console.error('Failed to parse log message:', e)
      }
    }

    ws.onerror = (error) => {
      console.error('WebSocket error:', error)
    }

    ws.onclose = () => {
      setIsConnected(false)
      console.log('WebSocket disconnected')
    }

    wsRef.current = ws

    return () => {
      ws.close()
    }
  }, [mode])

  // Keep isPausedRef in sync with isPaused state
  useEffect(() => {
    isPausedRef.current = isPaused
  }, [isPaused])

  // Auto-scroll for live mode
  useEffect(() => {
    if (mode === 'live' && !isPaused) {
      logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [liveLogs, mode, isPaused])

  const clearLiveLogs = useCallback(() => {
    setLiveLogs([])
  }, [])

  const handlePrevPage = () => {
    setFilter(f => ({ ...f, offset: Math.max(0, f.offset - f.limit) }))
  }

  const handleNextPage = () => {
    if (data && data.logs?.length === filter.limit) {
      setFilter(f => ({ ...f, offset: f.offset + f.limit }))
    }
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Logs</h1>
        <div className="flex items-center gap-3">
          {/* Mode toggle */}
          <div className="flex rounded-lg border border-gray-300 dark:border-gray-600 overflow-hidden">
            <button
              onClick={() => setMode('historical')}
              className={`px-3 py-1.5 text-sm font-medium ${
                mode === 'historical'
                  ? 'bg-runic-600 text-white'
                  : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
              }`}
            >
              Historical
            </button>
            <button
              onClick={() => setMode('live')}
              className={`px-3 py-1.5 text-sm font-medium flex items-center gap-1.5 ${
                mode === 'live'
                  ? 'bg-runic-600 text-white'
                  : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
              }`}
            >
              {isConnected ? (
                <Wifi className="w-3.5 h-3.5" />
              ) : (
                <WifiOff className="w-3.5 h-3.5" />
              )}
              Live
            </button>
          </div>

          {mode === 'historical' && (
            <button
              onClick={() => refetch()}
              className="flex items-center gap-2 px-3 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
            >
              <RefreshCw className="w-4 h-4" /> Refresh
            </button>
          )}

          {mode === 'live' && (
            <>
              <button
                onClick={() => setIsPaused(!isPaused)}
                className={`flex items-center gap-2 px-3 py-2 text-sm rounded-lg ${
                  isPaused
                    ? 'bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300'
                    : 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300'
                }`}
              >
                {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
                {isPaused ? 'Resume' : 'Pause'}
              </button>
              <button
                onClick={clearLiveLogs}
                className="flex items-center gap-2 px-3 py-2 text-sm text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/30 rounded-lg"
              >
                <Trash2 className="w-4 h-4" /> Clear
              </button>
            </>
          )}
        </div>
      </div>

      {/* Filter panel (historical mode) */}
      {mode === 'historical' && (
        <div className="flex flex-wrap gap-3 items-end bg-white dark:bg-gray-800 p-4 rounded-xl">
          <div className="space-y-1">
            <label className="text-xs font-medium text-gray-500 dark:text-gray-400">Server</label>
            <select
              value={filter.server_id}
              onChange={e => setFilter(f => ({ ...f, server_id: e.target.value, offset: 0 }))}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm min-w-[150px]"
            >
              <option value="">All servers</option>
              {peers?.map(s => (
                <option key={s.id} value={s.id}>{s.hostname}</option>
              ))}
            </select>
          </div>

          <div className="space-y-1">
            <label className="text-xs font-medium text-gray-500 dark:text-gray-400">Action</label>
            <select
              value={filter.action}
              onChange={e => setFilter(f => ({ ...f, action: e.target.value, offset: 0 }))}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="">All</option>
              <option value="ACCEPT">ACCEPT</option>
              <option value="DROP">DROP</option>
              <option value="BLOCK">BLOCK</option>
            </select>
          </div>

          <div className="space-y-1">
            <label className="text-xs font-medium text-gray-500 dark:text-gray-400">Source IP</label>
            <input
              type="text"
              placeholder="e.g. 192.168.1"
              value={filter.src_ip}
              onChange={e => setFilter(f => ({ ...f, src_ip: e.target.value, offset: 0 }))}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm w-32"
            />
          </div>

          <div className="space-y-1">
            <label className="text-xs font-medium text-gray-500 dark:text-gray-400">Dest Port</label>
            <input
              type="text"
              placeholder="e.g. 443"
              value={filter.dst_port}
              onChange={e => setFilter(f => ({ ...f, dst_port: e.target.value, offset: 0 }))}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm w-24"
            />
          </div>

          <div className="space-y-1">
            <label className="text-xs font-medium text-gray-500 dark:text-gray-400">Limit</label>
            <select
              value={filter.limit}
              onChange={e => setFilter(f => ({ ...f, limit: parseInt(e.target.value), offset: 0 }))}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value={50}>50 rows</option>
              <option value={100}>100 rows</option>
              <option value={200}>200 rows</option>
              <option value={500}>500 rows</option>
            </select>
          </div>

          <button
            onClick={() => refetch()}
            className="px-4 py-2 bg-runic-600 hover:bg-runic-700 text-white text-sm font-medium rounded-lg"
          >
            Query
          </button>
        </div>
      )}

      {/* Live mode status */}
      {mode === 'live' && (
        <div className="flex items-center gap-2 text-sm">
          <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
          <span className="text-gray-600 dark:text-gray-400">
            {isConnected ? `Connected — ${liveLogs.length} logs` : 'Disconnected'}
          </span>
        </div>
      )}

      {/* Logs display */}
      {!mode || (mode === 'historical' && isLoading) ? (
        <TableSkeleton rows={5} columns={6} />
      ) : null}

      {mode === 'historical' && data && (
        <>
          {!data.logs?.length ? (
            <EmptyState
              icon={FileText}
              title="No logs found"
              message="Try adjusting your filters or wait for agents to ship firewall events."
            />
          ) : (
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
              <div className="overflow-y-auto max-h-[600px]">
                {data.logs.map((log, i) => (
                  <LogLine key={log.id || i} log={log} />
                ))}
              </div>
              {/* Pagination */}
              <div className="flex items-center justify-between px-4 py-3 bg-gray-50 dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700">
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  Showing {filter.offset + 1} - {filter.offset + data.logs.length} of {data.total}
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={handlePrevPage}
                    disabled={filter.offset === 0}
                    className="px-3 py-1.5 text-sm bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg disabled:opacity-50"
                  >
                    Previous
                  </button>
                  <button
                    onClick={handleNextPage}
                    disabled={data.logs?.length < filter.limit}
                    className="px-3 py-1.5 text-sm bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg disabled:opacity-50"
                  >
                    Next
                  </button>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {mode === 'live' && (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
          <div className="overflow-y-auto max-h-[600px]">
            {!liveLogs.length ? (
              <div className="p-8 text-center text-gray-500 dark:text-gray-400">
                {isConnected ? 'Waiting for logs...' : 'Connecting...'}
              </div>
            ) : (
              liveLogs.map((log, i) => (
                <LogLine key={log.id || `${i}-${log.timestamp}`} log={log} />
              ))
            )}
            <div ref={logsEndRef} />
          </div>
        </div>
      )}
    </div>
  )
}
