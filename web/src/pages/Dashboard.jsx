import { useState, useEffect, useMemo, useRef } from 'react'
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
import { useWebSocket } from '../hooks/useWebSocket'
import { logger } from '../utils/logger'

export default function Dashboard() {
  const [liveBlockedCount, setLiveBlockedCount] = useState(0)
  const [liveActivity, setLiveActivity] = useState([])
  const [topSourcesUpdates, setTopSourcesUpdates] = useState({})
  // Full detail of live DROP events (timestamp + source IP) backing the
  // aggregate counters above, capped so the tab cannot grow unbounded.
  const liveEventsRef = useRef([])
  // Newest event timestamp covered by the last dashboard snapshot. Live
  // deltas at or below this watermark are already counted server-side.
  const watermarkRef = useRef(null)
  const MAX_LIVE_EVENTS = 1000

  const { data, isLoading } = useQuery({
    queryKey: QUERY_KEYS.dashboardStats(),
    queryFn: ({ signal }) => api.get('/dashboard', signal),
    staleTime: 30000, // Cache for 30 seconds
  })

  const { data: blockedLogs } = useQuery({
    queryKey: QUERY_KEYS.blockedLogs24h(),
    queryFn: async ({ signal }) => {
      const to = new Date()
      const from = new Date(to.getTime() - 24 * 60 * 60 * 1000)
      return api.get(`/logs?limit=1000&action=DROP&from=${from.toISOString()}&to=${to.toISOString()}`, signal)
    },
    refetchInterval: REFETCH_INTERVALS.DASHBOARD_LOGS, // Refresh every minute
    refetchIntervalInBackground: false,
    staleTime: 30000,
  })

  const { totalPendingCount } = usePendingChanges()

  // Rebase live deltas against each fresh snapshot instead of clearing
  // them: drop only the events the new server data already covers (by
  // timestamp watermark) and keep newer ones, so live counts neither
  // flicker to zero nor double-count on refetch.
  useEffect(() => {
    if (!data) return
    const activity = Array.isArray(data.recent_activity) ? data.recent_activity : []
    const serverLatest = activity.reduce((latest, a) => {
      const ts = new Date(a?.timestamp).getTime()
      return Number.isFinite(ts) ? Math.max(latest, ts) : latest
    }, 0)
    // No real server timestamps (empty/invalid snapshot): leave the watermark
    // unset so the first live DROP after the snapshot is kept, not dropped.
    if (!serverLatest) {
      watermarkRef.current = null
      return
    }
    watermarkRef.current = serverLatest
    const remaining = liveEventsRef.current.filter(e => e.ts > serverLatest)
    liveEventsRef.current = remaining
    setLiveBlockedCount(remaining.length)
    setLiveActivity(prev => prev.filter(a => {
      const ts = new Date(a.timestamp).getTime()
      return Number.isFinite(ts) && ts > serverLatest
    }))
    const rebuilt = {}
    for (const e of remaining) {
      if (e.ip) rebuilt[e.ip] = (rebuilt[e.ip] || 0) + 1
    }
    setTopSourcesUpdates(rebuilt)
  }, [data])

  // WebSocket connection for live blocked events
  const wsProto = typeof window !== 'undefined' && window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const wsHost = typeof window !== 'undefined' ? window.location.host : ''
  const wsUrl = `${wsProto}//${wsHost}/api/v1/logs/stream?action=DROP`

  const { connected: isWsConnected } = useWebSocket({
    url: wsUrl,
    enabled: true,
    maxRetries: 5,
    onMessage: (event) => {
      try {
        const log = JSON.parse(event.data)

        // Only process DROP events (should be filtered by server, but double-check)
        if (log.action !== 'DROP') return

        const timestamp = log.timestamp || new Date().toISOString()
        const ts = new Date(timestamp).getTime()
        // Skip events the current snapshot already covers so a reconnect
        // replay cannot double-count them.
        if (watermarkRef.current != null && Number.isFinite(ts) && ts <= watermarkRef.current) return

        liveEventsRef.current = [...liveEventsRef.current, { ts: Number.isFinite(ts) ? ts : Date.now(), ip: log.src_ip || '' }].slice(-MAX_LIVE_EVENTS)

        setLiveBlockedCount(prev => prev + 1)

        setLiveActivity(prev => {
          const newActivity = {
            timestamp,
            src_ip: log.src_ip,
            dst_ip: log.dst_ip,
            protocol: log.protocol,
            action: log.action,
            hostname: log.hostname || '',
          }
          return [newActivity, ...prev].slice(0, 5)
        })

        if (log.src_ip) {
          setTopSourcesUpdates(prev => ({
            ...prev,
            [log.src_ip]: (prev[log.src_ip] || 0) + 1,
          }))
        }
      } catch (e) {
        logger.error('Failed to parse WebSocket message:', e)
      }
    },
  })

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

  const combinedActivity = useMemo(() => {
    const serverActivity = stats.recent_activity || []
    if (liveActivity.length === 0) return serverActivity
    if (serverActivity.length === 0) return liveActivity
    const seen = new Set()
    const merged = []
    for (const item of [...liveActivity, ...serverActivity]) {
      const key = `${item?.timestamp}|${item?.src_ip}|${item?.dst_ip}|${item?.protocol}`
      if (seen.has(key)) continue
      seen.add(key)
      merged.push(item)
    }
    return merged
  }, [liveActivity, stats.recent_activity])

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

      <div className="border border-gray-border bg-charcoal-dark p-4">
        <h2 className="font-semibold text-gray-900 dark:text-light-neutral mb-4">Blocked Events (Last 24 Hours)</h2>
        <BlockedEventsChart logs={blockedLogs?.logs || []} />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-0">
        <RecentActivityFeed activity={combinedActivity} />
        <QuickActions />
        <TopBlockedSources sources={topSources} />
      </div>
    </div>
  )
}
