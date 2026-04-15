import { useState, useEffect, useRef, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, QUERY_KEYS } from '../api/client'
import { REFETCH_INTERVALS } from '../constants'
import StatCard from '../components/StatCard'
import BlockedEventsChart from '../components/BlockedEventsChart'
import TableSkeleton from '../components/TableSkeleton'
import RecentActivityFeed from '../components/RecentActivityFeed'
import QuickActions from '../components/QuickActions'
import TopBlockedSources from '../components/TopBlockedSources'
import { Server, Shield, AlertTriangle, Clock, UserPlus, Wifi, WifiOff } from 'lucide-react'
import { usePendingChanges } from '../contexts/PendingChangesContext'

export default function Dashboard() {
  // Track live updates from WebSocket
  const [liveBlockedCount, setLiveBlockedCount] = useState(0)
  const [liveActivity, setLiveActivity] = useState([])
  const [topSourcesUpdates, setTopSourcesUpdates] = useState({})
  const [isWsConnected, setIsWsConnected] = useState(false)
  const wsRef = useRef(null)
  const reconnectAttempts = useRef(0)
  const reconnectTimer = useRef(null)

  // Fetch dashboard stats
  const { data, isLoading } = useQuery({
    queryKey: QUERY_KEYS.dashboardStats(),
    queryFn: () => api.get('/dashboard'),
    staleTime: 30000, // Cache for 30 seconds
  })

  // Logs query for chart
  const { data: blockedLogs } = useQuery({
    queryKey: QUERY_KEYS.blockedLogs24h(),
    queryFn: async () => {
      const to = new Date()
      const from = new Date(to.getTime() - 24 * 60 * 60 * 1000)
      return api.get(`/logs?limit=1000&action=DROP&from=${from.toISOString()}&to=${to.toISOString()}`)
    },
    refetchInterval: REFETCH_INTERVALS.DASHBOARD_LOGS, // Refresh every minute
    refetchIntervalInBackground: false,
    staleTime: 30000,
  })

  // Get pending changes from context
  const { totalPendingCount } = usePendingChanges()

  // Reset live state when query data refreshes
  useEffect(() => {
    if (data) {
      setLiveBlockedCount(0)
      setLiveActivity([])
      setTopSourcesUpdates({})
    }
  }, [data])

  // WebSocket connection for real-time updates
  useEffect(() => {
    const connect = () => {
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }

      const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const wsUrl = `${wsProto}//${window.location.host}/api/v1/logs/stream?action=DROP`

      // Authentication is handled via HttpOnly cookies (runic_access_token)
      // which are automatically sent with the WebSocket upgrade request.
      // The server checks cookies first before falling back to Sec-WebSocket-Protocol header.
      const ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        reconnectAttempts.current = 0
        setIsWsConnected(true)
      }

      ws.onmessage = (event) => {
        try {
          const log = JSON.parse(event.data)

          // Only process DROP events (should be filtered by server, but double-check)
          if (log.action !== 'DROP') return

          // Increment blocked count
          setLiveBlockedCount(prev => prev + 1)

          // Add to recent activity (newest first)
          setLiveActivity(prev => {
            const newActivity = {
              timestamp: log.timestamp || new Date().toISOString(),
              src_ip: log.src_ip,
              dst_ip: log.dst_ip,
              protocol: log.protocol,
              action: log.action,
              hostname: log.hostname || '',
            }
            // Keep only last 5, newest first
            return [newActivity, ...prev].slice(0, 5)
          })

          // Update top blocked sources count
          if (log.src_ip) {
            setTopSourcesUpdates(prev => ({
              ...prev,
              [log.src_ip]: (prev[log.src_ip] || 0) + 1,
            }))
          }
        } catch (e) {
          console.error('Failed to parse WebSocket message:', e)
        }
      }

      ws.onclose = () => {
        setIsWsConnected(false)
        // Reconnect with exponential backoff
        if (reconnectAttempts.current < 5) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000)
          reconnectTimer.current = setTimeout(() => {
            reconnectAttempts.current++
            connect()
          }, delay)
        }
      }

      ws.onerror = () => {
        ws.close()
      }

      wsRef.current = ws
    }

    connect()

    return () => {
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current)
      }
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }
    }
  }, [])

  // Merge live updates with fetched data
  const stats = data || {
    total_peers: 0,
    online_peers: 0,
    offline_peers: 0,
    manual_peers: 0,
    total_policies: 0,
    blocked_last_hour: 0,
    blocked_last_24h: 0,
    recent_activity: [],
    peer_health: [],
    top_blocked_sources: []
  }

  // Combine API recent activity with live updates
  const combinedActivity = liveActivity.length > 0
    ? liveActivity
    : stats.recent_activity || []

  // Use useMemo for combinedTopSources (performance optimization)
  const topSources = useMemo(() => {
    const combined = [...(stats.top_blocked_sources || [])].map(source => ({
      ...source,
      count: source.count + (topSourcesUpdates[source.src_ip] || 0),
    }))

    // Add any new sources from live updates that aren't in top 5
    Object.entries(topSourcesUpdates).forEach(([ip, count]) => {
      if (!combined.find(s => s.src_ip === ip)) {
        combined.push({ src_ip: ip, count })
      }
    })

    // Sort by count and take top 5
    combined.sort((a, b) => b.count - a.count)
    return combined.slice(0, 5)
  }, [stats.top_blocked_sources, topSourcesUpdates])

  if (isLoading) return <TableSkeleton rows={4} columns={5} />

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-light-neutral">Dashboard</h1>

        {/* WebSocket connection status */}
        <div className="flex items-center gap-2 text-sm">
          {isWsConnected ? (
            <div className="flex items-center gap-1.5 text-green-600 dark:text-green-400">
              <Wifi className="w-4 h-4" />
              <span>Live</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 text-gray-500 dark:text-gray-400">
              <WifiOff className="w-4 h-4" />
              <span>Reconnecting...</span>
            </div>
          )}
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-0">
        <StatCard icon={Server} label="Total Peers" value={stats.total_peers} valueColor="text-slate-400" />
        <StatCard icon={Server} label="Online" value={stats.online_peers} valueColor="text-green-500" />
        <StatCard icon={Server} label="Offline" value={stats.offline_peers} valueColor={stats.offline_peers > 0 ? 'text-red-500' : 'text-slate-400'} />
        <StatCard icon={UserPlus} label="Manual Peers" value={stats.manual_peers} valueColor="text-slate-400" />
        <StatCard icon={Shield} label="Active Policies" value={stats.total_policies} valueColor="text-blue-400" />
        <StatCard icon={AlertTriangle} label="Pending Changes" value={totalPendingCount} valueColor={totalPendingCount > 0 ? 'text-orange-500' : 'text-slate-400'} />
        <StatCard icon={AlertTriangle} label="Blocked (1h)" value={stats.blocked_last_hour + liveBlockedCount} valueColor={(stats.blocked_last_hour + liveBlockedCount) > 0 ? 'text-purple-active' : 'text-slate-400'} />
        <StatCard icon={Clock} label="Blocked (24h)" value={stats.blocked_last_24h + liveBlockedCount} valueColor={(stats.blocked_last_24h + liveBlockedCount) > 0 ? 'text-purple-active' : 'text-slate-400'} />
      </div>

  {/* Blocked events chart */}
  <div className="border border-gray-border bg-charcoal-dark p-4">
    <h2 className="font-semibold text-gray-900 dark:text-light-neutral mb-4">Blocked Events (Last 24 Hours)</h2>
    <BlockedEventsChart logs={blockedLogs?.logs || []} />
  </div>

      {/* Dashboard Widgets */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-0">
        <RecentActivityFeed activity={combinedActivity} />
        <QuickActions />
        <TopBlockedSources sources={topSources} />
      </div>
    </div>
  )
}
