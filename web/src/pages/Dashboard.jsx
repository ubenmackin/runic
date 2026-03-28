import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, QUERY_KEYS } from '../api/client'
import StatusBadge from '../components/StatusBadge'
import StatCard from '../components/StatCard'
import BlockedEventsChart from '../components/BlockedEventsChart'
import TableSkeleton from '../components/TableSkeleton'
import { Server, Shield, AlertTriangle, Clock, Router, ArrowUpRight, FileText, Plus } from 'lucide-react'
import { Link } from 'react-router-dom'

export default function Dashboard() {
  const qc = useQueryClient()

  // Combined initial query for dashboard stats and peers (parallel fetch)
  const { data: combinedData, isLoading } = useQuery({
    queryKey: ['dashboard-initial'],
    queryFn: async () => {
      const [dashboard, peers] = await Promise.all([
        api.get('/dashboard'),
        api.get('/peers'),
      ])
      return { dashboard, peers }
    },
    staleTime: 30000, // Cache for 30 seconds
  })

  const data = combinedData?.dashboard
  const peersFromCombined = combinedData?.peers

  // Separate query for peers with auto-refresh (for real-time status updates)
  const peersQuery = useQuery({
    queryKey: QUERY_KEYS.peers(),
    queryFn: () => api.get('/peers'),
    initialData: peersFromCombined, // Use data from combined query as initial value
    refetchInterval: 15000, // 15 seconds - balance between freshness and network efficiency
    refetchIntervalInBackground: false, // Don't poll when tab is hidden
    refetchOnReconnect: true, // Refetch when network reconnects
    refetchOnWindowFocus: true, // Refetch when user returns to tab
    staleTime: 10000, // Consider data fresh for 10 seconds
  })

  const pushAllMutation = useMutation({
    mutationFn: async (peerId) => {
      await api.post(`/peers/${peerId}/push`)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QUERY_KEYS.peers() })
    },
  })

const handlePushAll = async () => {
  if (!peersQuery.data) return
  await Promise.all(peersQuery.data.map(peer => pushAllMutation.mutateAsync(peer.id)))
}

  // Logs query for chart
  const { data: blockedLogs } = useQuery({
    queryKey: QUERY_KEYS.blockedLogs24h(),
    queryFn: async () => {
      const to = new Date()
      const from = new Date(to.getTime() - 24 * 60 * 60 * 1000)
      return api.get(`/logs?limit=1000&action=DROP&from=${from.toISOString()}&to=${to.toISOString()}`)
    },
    refetchInterval: 60000, // Refresh every minute - appropriate for historical chart data
    refetchIntervalInBackground: false, // Don't poll when tab is hidden
    staleTime: 30000, // Consider data fresh for 30 seconds
  })

  if (isLoading) return <TableSkeleton rows={4} columns={5} />

  const stats = data || { total_peers: 0, online_peers: 0, offline_peers: 0, total_policies: 0, blocked_last_hour: 0, blocked_last_24h: 0 }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
        <div className="flex gap-2">
          <Link
            to="/logs"
            className="flex items-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg"
          >
            <FileText className="w-4 h-4" /> View Logs
          </Link>
          <button
            onClick={handlePushAll}
            disabled={pushAllMutation.isPending || !peersQuery.data?.length}
            className="px-4 py-2 bg-runic-600 hover:bg-runic-700 text-white text-sm font-medium rounded-lg disabled:opacity-50"
          >
            {pushAllMutation.isPending ? 'Pushing...' : 'Push All Rules'}
          </button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
<StatCard icon={Server} label="Total Peers" value={stats.total_peers} />
      <StatCard icon={Server} label="Online" value={stats.online_peers} color="text-green-600" />
      <StatCard icon={Server} label="Offline" value={stats.offline_peers} color="text-red-600" />
        <StatCard icon={Shield} label="Active Policies" value={stats.total_policies} />
        <StatCard icon={AlertTriangle} label="Blocked (1h)" value={stats.blocked_last_hour} />
        <StatCard icon={Clock} label="Blocked (24h)" value={stats.blocked_last_24h} />
      </div>

      {/* Blocked events chart */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4">
        <h2 className="font-semibold text-gray-900 dark:text-white mb-4">Blocked Events (Last 24 Hours)</h2>
        <BlockedEventsChart logs={blockedLogs?.logs || []} />
      </div>

      {/* Server status table */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
          <h2 className="font-semibold text-gray-900 dark:text-white">Peer Status</h2>
      <Link
        to="/peers"
        className="flex items-center gap-1 text-sm text-runic-600 hover:text-runic-700 dark:text-runic-400"
      >
        View All <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 dark:bg-gray-900">
              <tr>
                <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400">Hostname</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400">IP</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400">Status</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400">Last Heartbeat</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-gray-400">Bundle</th>
              </tr>
            </thead>
<tbody className="divide-y divide-gray-200 dark:divide-gray-700">
          {peersQuery.data?.map(peer => (
            <tr key={peer.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${
                      peer.status === 'online' ? 'bg-green-500' :
                      peer.status === 'offline' ? 'bg-red-500' :
                      'bg-amber-500' // pending
                    }`} />
                    <span className="text-gray-900 dark:text-white font-medium">{peer.hostname}</span>
                  </div>
                </td>
              <td className="px-4 py-3 text-gray-500 dark:text-gray-400">{peer.ip_address}</td>
              <td className="px-4 py-3"><StatusBadge status={peer.status} /></td>
              <td className="px-4 py-3 text-gray-500 dark:text-gray-400">
                {formatRelativeTime(peer.last_heartbeat)}
              </td>
              <td className="px-4 py-3 text-gray-500 dark:text-gray-400">v{peer.bundle_version || 0}</td>
            </tr>
          ))}
          {!peersQuery.data?.length && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                    <div className="flex flex-col items-center gap-2">
                      <Router className="w-8 h-8 text-gray-400" />
<span>No peers registered</span>
        <Link
          to="/peers"
          className="flex items-center gap-1 px-3 py-1.5 bg-runic-600 hover:bg-runic-700 text-white text-sm rounded-lg"
        >
          <Plus className="w-4 h-4" /> Add Peer
              </Link>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Quick actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link
          to="/policies"
          className="flex items-center gap-3 p-4 bg-white dark:bg-gray-800 rounded-xl shadow-sm hover:shadow-md transition-shadow"
        >
          <div className="p-2 bg-runic-100 dark:bg-runic-900 rounded-lg">
            <Shield className="w-5 h-5 text-runic-600 dark:text-runic-400" />
          </div>
          <div>
            <div className="font-medium text-gray-900 dark:text-white">Manage Policies</div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Create and edit firewall rules</div>
          </div>
        </Link>

    <Link
      to="/peers"
      className="flex items-center gap-3 p-4 bg-white dark:bg-gray-800 rounded-xl shadow-sm hover:shadow-md transition-shadow"
    >
      <div className="p-2 bg-runic-100 dark:bg-runic-900 rounded-lg">
        <Server className="w-5 h-5 text-runic-600 dark:text-runic-400" />
      </div>
      <div>
        <div className="font-medium text-gray-900 dark:text-white">Manage Peers</div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Add or configure agents</div>
          </div>
        </Link>

        <Link
          to="/logs"
          className="flex items-center gap-3 p-4 bg-white dark:bg-gray-800 rounded-xl shadow-sm hover:shadow-md transition-shadow"
        >
          <div className="p-2 bg-runic-100 dark:bg-runic-900 rounded-lg">
            <FileText className="w-5 h-5 text-runic-600 dark:text-runic-400" />
          </div>
          <div>
            <div className="font-medium text-gray-900 dark:text-white">View Logs</div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Monitor firewall events in real-time</div>
          </div>
        </Link>
      </div>
    </div>
  )
}

function formatRelativeTime(timestamp) {
  if (!timestamp) return 'Never'

  const date = new Date(timestamp)
  const now = new Date()
  const diffMs = now - date
  const diffSecs = Math.floor(diffMs / 1000)
  const diffMins = Math.floor(diffSecs / 60)
  const diffHours = Math.floor(diffMins / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffSecs < 60) return 'Just now'
  if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`
  if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`

  return date.toLocaleDateString()
}
