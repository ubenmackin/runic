import { useQuery } from '@tanstack/react-query'
import { api, QUERY_KEYS } from '../api/client'
import { REFETCH_INTERVALS } from '../constants'
import StatCard from '../components/StatCard'
import BlockedEventsChart from '../components/BlockedEventsChart'
import TableSkeleton from '../components/TableSkeleton'
import RecentActivityFeed from '../components/RecentActivityFeed'
import QuickActions from '../components/QuickActions'
import TopBlockedSources from '../components/TopBlockedSources'
import { Server, Shield, AlertTriangle, Clock, UserPlus } from 'lucide-react'
import { usePendingChanges } from '../contexts/PendingChangesContext'

export default function Dashboard() {
  // Fetch dashboard stats
  const { data, isLoading } = useQuery({
    queryKey: ['dashboard-stats'],
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
    refetchInterval: REFETCH_INTERVALS.DASHBOARD_LOGS, // Refresh every minute - appropriate for historical chart data
    refetchIntervalInBackground: false, // Don't poll when tab is hidden
    staleTime: 30000, // Consider data fresh for 30 seconds
  })

  // Get pending changes from context (shared with Layout)
  const { totalPendingCount } = usePendingChanges()

  if (isLoading) return <TableSkeleton rows={4} columns={5} />

  const stats = data || { total_peers: 0, online_peers: 0, offline_peers: 0, manual_peers: 0, total_policies: 0, blocked_last_hour: 0, blocked_last_24h: 0, recent_activity: [], peer_health: [], top_blocked_sources: [] }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-light-neutral">Dashboard</h1>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard icon={AlertTriangle} label="Pending Changes" value={totalPendingCount} color={totalPendingCount > 0 ? "text-amber-600" : ""} />
        <StatCard icon={Server} label="Total Peers" value={stats.total_peers} />
        <StatCard icon={Server} label="Online" value={stats.online_peers} color="text-green-600" />
        <StatCard icon={Server} label="Offline" value={stats.offline_peers} color="text-red-600" />
        <StatCard icon={UserPlus} label="Manual Peers" value={stats.manual_peers} color="text-purple-600" />
        <StatCard icon={Shield} label="Active Policies" value={stats.total_policies} />
        <StatCard icon={AlertTriangle} label="Blocked (1h)" value={stats.blocked_last_hour} />
        <StatCard icon={Clock} label="Blocked (24h)" value={stats.blocked_last_24h} />
      </div>

      {/* Blocked events chart */}
      <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm p-4">
        <h2 className="font-semibold text-gray-900 dark:text-light-neutral mb-4">Blocked Events (Last 24 Hours)</h2>
        <BlockedEventsChart logs={blockedLogs?.logs || []} />
      </div>

      {/* Dashboard Widgets */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <RecentActivityFeed activity={stats.recent_activity || []} />
        <QuickActions />
        <TopBlockedSources sources={stats.top_blocked_sources || []} />
      </div>
    </div>
  )
}
