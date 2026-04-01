import { Activity } from 'lucide-react'

function getRelativeTime(timestamp) {
  const now = new Date()
  const then = new Date(timestamp)
  const diffMs = now - then
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMins / 60)
  if (diffMins < 1) return 'Just now'
  if (diffMins < 60) return `${diffMins} min ago`
  if (diffHours < 24) return `${diffHours}h ago`
  return `${Math.floor(diffHours / 24)}d ago`
}

export default function RecentActivityFeed({ activity }) {
  return (
    <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm p-4">
      <div className="flex items-center gap-2 mb-4">
        <Activity className="w-5 h-5 text-purple-active" />
        <h3 className="text-sm font-semibold text-gray-900 dark:text-light-neutral">Recent Activity</h3>
      </div>
      
      {activity.length === 0 ? (
        <p className="text-sm text-gray-400 dark:text-amber-muted text-center py-4">
          No recent blocked events
        </p>
      ) : (
        <div className="space-y-3">
          {activity.map((item, idx) => (
            <div key={idx} className="border-b border-gray-100 dark:border-gray-border pb-3 last:border-0 last:pb-0">
              <p className="text-xs text-gray-500 dark:text-amber-muted mb-1">
                {getRelativeTime(item.timestamp)}
              </p>
              <div className="flex items-center gap-1 flex-wrap">
                <span className="text-sm font-mono text-gray-900 dark:text-white">{item.src_ip}</span>
                <span className="text-gray-400 mx-1">→</span>
                <span className="text-sm font-mono font-semibold text-gray-900 dark:text-white">{item.dst_ip}</span>
                <span className="px-2 py-0.5 text-xs rounded bg-gray-100 dark:bg-charcoal-darkest text-gray-600 dark:text-amber-muted ml-1">
                  {item.protocol}
                </span>
                {item.hostname && (
                  <span className="text-xs text-gray-400 dark:text-gray-500 ml-2">
                    {item.hostname}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
