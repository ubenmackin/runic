import { useState, useEffect, useRef, useCallback } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { FileText, Play, Pause, Trash2, Wifi, WifiOff, X } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useDebounce } from '../hooks/useDebounce'
import { useAuth } from '../hooks/useAuth'
import { useToastContext } from '../hooks/ToastContext'
import EmptyState from '../components/EmptyState'
import TableSkeleton from '../components/TableSkeleton'
import LogLine from '../components/LogLine'
import CraftPolicyWizard from '../components/CraftPolicyWizard'
import SearchableSelect from '../components/SearchableSelect'
import PageHeader from '../components/PageHeader'
import Pagination from '../components/Pagination'
import SearchFilterPanel from '../components/SearchFilterPanel'
import { logger } from '../utils/logger'

const MAX_RECONNECT_ATTEMPTS = 5

export default function Logs() {
  const [mode, setMode] = useState('historical') // 'live' | 'historical'
  const [filter, setFilter] = useState({
    peer_id: '',
    action: '',
    src_ip: '',
    dst_port: '',
    from: '',
    to: '',
    limit: 100,
    offset: 0,
  })

  const debouncedFilter = useDebounce(filter)

  const [liveLogs, setLiveLogs] = useState([])
  const [isConnected, setIsConnected] = useState(false)
  const [isReconnecting, setIsReconnecting] = useState(false)
  const [reconnectAttemptDisplay, setReconnectAttemptDisplay] = useState(0)
  const [isPaused, setIsPaused] = useState(false)
  const wsRef = useRef(null)
  const logsEndRef = useRef(null)
  const isPausedRef = useRef(false)
  const reconnectAttempts = useRef(0)
  const reconnectTimer = useRef(null)
  const MAX_LIVE_LOGS = 500 // Maximum logs to keep in live mode memory

  // Ref to track current mode in callbacks (avoid stale closures)
  const modeRef = useRef(mode)

  const queryClient = useQueryClient()
  const { canEdit } = useAuth()
  const showToast = useToastContext()

  // Craft Policy Wizard state
  const [wizardOpen, setWizardOpen] = useState(false)
  const [wizardLog, setWizardLog] = useState(null)

  const handleCraftPolicy = (log) => {
    setWizardLog(log)
    setWizardOpen(true)
  }

  // Keep modeRef in sync with mode state
  useEffect(() => {
    modeRef.current = mode
  }, [mode])

  const { data, isLoading, refetch } = useQuery({
    queryKey: QUERY_KEYS.logs(debouncedFilter),
    queryFn: () => api.get(`/logs?${new URLSearchParams(
      Object.entries(debouncedFilter).filter(([_, v]) => v !== '').map(([k, v]) => [k, String(v)])
    )}`),
    enabled: mode === 'historical',
    refetchInterval: mode === 'historical' ? false : false,
  })

  const { data: peers } = useQuery({
    queryKey: QUERY_KEYS.peers(),
    queryFn: () => api.get('/peers'),
  })

  useEffect(() => {
    if (mode !== 'live') {
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current)
        reconnectTimer.current = null
      }
      reconnectAttempts.current = 0
      return
    }

    // Reset reconnect attempts when entering live mode
    reconnectAttempts.current = 0

  const connect = () => {
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }

    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${wsProto}//${window.location.host}/api/v1/logs/stream`

    // Authentication is handled via HttpOnly cookies (runic_access_token)
    // which are automatically sent with the WebSocket upgrade request.
    // The server checks cookies first before falling back to Sec-WebSocket-Protocol header.
    const ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        setIsConnected(true)
        reconnectAttempts.current = 0
        setReconnectAttemptDisplay(0)
        setIsReconnecting(false)
        logger.log('WebSocket connected')
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
          logger.error('Failed to parse log message:', e)
        }
      }

      ws.onerror = (error) => {
        logger.error('WebSocket error:', error)
      }

    ws.onclose = () => {
      setIsConnected(false)
      logger.log('WebSocket disconnected')

      if (modeRef.current !== 'live') return
      if (reconnectAttempts.current >= MAX_RECONNECT_ATTEMPTS) {
        setIsReconnecting(false)
        return
      }
      setIsReconnecting(true)
      setReconnectAttemptDisplay(reconnectAttempts.current + 1)
      const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000)
      reconnectTimer.current = setTimeout(() => {
        reconnectAttempts.current++
        connect()
      }, delay)
    }

    wsRef.current = ws
    }

    connect()

    return () => {
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current)
        reconnectTimer.current = null
      }
      setReconnectAttemptDisplay(0)
    }
  }, [mode])

  // Keep isPausedRef in sync with isPaused state
  useEffect(() => {
    isPausedRef.current = isPaused
  }, [isPaused])

  useEffect(() => {
    if (mode === 'live' && !isPaused) {
      logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [liveLogs, mode, isPaused])

  const clearLiveLogs = useCallback(() => {
    setLiveLogs([])
  }, [])

  const _handlePrevPage = () => {
    setFilter(f => ({ ...f, offset: Math.max(0, f.offset - f.limit) }))
  }

  const _handleNextPage = () => {
    if (data && data.logs?.length === filter.limit) {
      setFilter(f => ({ ...f, offset: f.offset + f.limit }))
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Logs"
        description="View firewall events and blocked traffic"
        actions={
          <div className="flex items-center gap-3">
            <div className="flex rounded-none border border-gray-300 dark:border-gray-border overflow-hidden">
            <button
              onClick={() => setMode('historical')}
              className={`px-4 py-1.5 text-sm font-medium ${
                mode === 'historical'
                  ? 'bg-purple-active text-white'
                  : 'bg-white dark:bg-charcoal-dark text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest'
              }`}
            >
              Historical
            </button>
            <button
              onClick={() => setMode('live')}
              className={`px-4 py-1.5 text-sm font-medium flex items-center gap-1.5 ${
                mode === 'live'
                  ? 'bg-purple-active text-white'
                  : 'bg-white dark:bg-charcoal-dark text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest'
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

            {mode === 'live' && (
              <>
                <button
                  onClick={() => setIsPaused(!isPaused)}
className={`flex items-center gap-2 px-3 py-2 text-sm rounded-none ${
isPaused
? 'bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300'
: 'bg-gray-100 text-gray-700 dark:bg-charcoal-darkest dark:text-amber-primary'
}`}
                >
                  {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
                  {isPaused ? 'Resume' : 'Pause'}
                </button>
                <button
                  onClick={clearLiveLogs}
                  className="flex items-center gap-2 px-3 py-2 text-sm text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/30 rounded-none"
                >
                  <Trash2 className="w-4 h-4" /> Clear
                </button>
              </>
            )}
          </div>
        }
        />

        {mode === 'historical' && (
          <SearchFilterPanel
          storageKey="logs-filters-expanded"
          showSearch={false}
          hasActiveFilters={!!(filter.peer_id || filter.src_ip || filter.dst_port)}
          filterContent={
            <div className="flex items-center gap-4">
              <div className="space-y-1 min-w-[200px]">
                <label className="text-xs font-medium text-gray-500 dark:text-amber-muted">Peer</label>
                <SearchableSelect
                  options={(peers || []).map(p => ({ value: p.id, label: p.hostname }))}
                  value={filter.peer_id}
                  onChange={v => setFilter(f => ({ ...f, peer_id: v, offset: 0 }))}
                  placeholder="All peers"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-500 dark:text-amber-muted">Source IP</label>
                <input
                  type="text"
                  placeholder="e.g. 192.168.1"
                  value={filter.src_ip}
                  onChange={e => setFilter(f => ({ ...f, src_ip: e.target.value, offset: 0 }))}
                  className="px-3 py-2 border border-gray-300 dark:border-gray-border bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral text-sm w-32 focus:ring-2 focus:ring-purple-active focus:border-purple-active rounded-none"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-500 dark:text-amber-muted">Dest Port</label>
                <input
                  type="text"
                  placeholder="e.g. 443"
                  value={filter.dst_port}
                  onChange={e => setFilter(f => ({ ...f, dst_port: e.target.value, offset: 0 }))}
                  className="px-3 py-2 border border-gray-300 dark:border-gray-border bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral text-sm w-24 focus:ring-2 focus:ring-purple-active focus:border-purple-active rounded-none"
                />
              </div>
            </div>
          }
          rightContent={
            <div className="flex gap-4 items-end">
              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-500 dark:text-amber-muted">Limit</label>
                <select
                  value={filter.limit}
                  onChange={e => setFilter(f => ({ ...f, limit: parseInt(e.target.value), offset: 0 }))}
                  className="px-3 py-2 border border-gray-300 dark:border-gray-border bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral text-sm focus:ring-2 focus:ring-purple-active focus:border-purple-active rounded-none"
                >
                  <option value={50}>50 rows</option>
                  <option value={100}>100 rows</option>
                  <option value={200}>200 rows</option>
                  <option value={500}>500 rows</option>
                </select>
              </div>

              <button
                onClick={() => refetch()}
                className="px-4 py-2 bg-purple-active hover:bg-purple-600 text-white text-sm font-bold uppercase border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all"
              >
                Query
              </button>

              {(filter.peer_id || filter.src_ip || filter.dst_port) && (
                <button
                  onClick={() => setFilter(f => ({
                    ...f,
                    peer_id: '',
                    src_ip: '',
                    dst_port: '',
                    offset: 0,
                  }))}
                  className="flex items-center gap-1 px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20"
                >
                  <X className="w-4 h-4" />
                  Clear
                </button>
              )}
            </div>
          }
        />
      )}

      {mode === 'live' && (
        <div className="flex items-center gap-2 text-sm">
<div className={`w-2 h-2 rounded-full ${
                  isReconnecting ? 'bg-yellow-500 animate-pulse' :
                  isConnected ? 'bg-green-500 animate-pulse shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]'
                }`} />
          <span className="text-gray-600 dark:text-amber-muted">
            {isReconnecting
              ? `Reconnecting... (attempt ${reconnectAttemptDisplay}/${MAX_RECONNECT_ATTEMPTS})`
              : isConnected
                ? `Connected — ${liveLogs.length} logs`
                : 'Disconnected'}
          </span>
        </div>
        )}

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
<div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none overflow-hidden">
          <div className="overflow-y-auto max-h-[600px]">
                {data.logs.map((log, i) => (
                  <LogLine key={log.id || i} log={log} onCraftPolicy={handleCraftPolicy} canEdit={canEdit} />
                ))}
              </div>
              <Pagination
showingRange={`Showing ${filter.offset + 1} - ${filter.offset + data.logs.length} of ${data.total}`}
page={Math.floor(filter.offset / filter.limit) + 1}
totalPages={Math.ceil(data.total / filter.limit)}
onPageChange={(newPage) => setFilter(f => ({ ...f, offset: (newPage - 1) * f.limit }))}
totalItems={data.total}
/>
            </div>
          )}
        </>
      )}

      {mode === 'live' && (
        <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none overflow-hidden">
          <div className="overflow-y-auto max-h-[600px]">
            {!liveLogs.length ? (
              <div className="p-8 text-center text-gray-500 dark:text-amber-muted">
                {isReconnecting ? 'Reconnecting...' :
                 isConnected ? 'Waiting for logs...' :
                 'Connecting...'}
              </div>
            ) : (
              liveLogs.map((log, i) => (
                <LogLine key={log.id || `${i}-${log.timestamp}`} log={log} onCraftPolicy={handleCraftPolicy} canEdit={canEdit} />
              ))
            )}
        <div ref={logsEndRef} />
        </div>
      </div>
      )}

      {wizardOpen && wizardLog && (
        <CraftPolicyWizard
          log={wizardLog}
          onClose={() => setWizardOpen(false)}
          onSuccess={() => {
            setWizardOpen(false)
            queryClient.invalidateQueries({ queryKey: QUERY_KEYS.policies() })
            queryClient.invalidateQueries({ queryKey: QUERY_KEYS.peers() })
            queryClient.invalidateQueries({ queryKey: QUERY_KEYS.services() })
            showToast('Policy created successfully', 'success')
          }}
        />
      )}
    </div>
  )
}
