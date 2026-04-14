import { ShieldAlert } from 'lucide-react'

export default function TopBlockedSources({ sources }) {
  // Calculate max count for proportional bars
  const maxCount = sources.length > 0 ? sources[0].count : 1

  return (
    <div className="border border-gray-border bg-charcoal-dark p-4">
      <div className="flex items-center gap-2 mb-4">
        <ShieldAlert className="w-5 h-5 text-purple-active" />
        <h3 className="text-sm font-semibold text-gray-900 dark:text-light-neutral">
          Top Blocked Sources
        </h3>
        <span className="text-xs text-gray-400 dark:text-amber-muted">(24h)</span>
      </div>

      {sources.length === 0 ? (
        <p className="text-sm text-gray-400 dark:text-amber-muted text-center py-4">
          No blocked sources in last 24h
        </p>
      ) : (
        <div className="space-y-0">
          {sources.map((source, idx) => {
            const barWidth = (source.count / maxCount) * 100
            const showBar = sources.length >= 2

            return (
              <div
                key={source.src_ip}
                className="py-2 border-b border-gray-100 dark:border-gray-border last:border-0"
              >
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-gray-500 w-6">
                    {idx + 1}.
                  </span>
                  <span className="font-mono text-sm text-gray-900 dark:text-light-neutral flex-1">
                    {source.src_ip}
                  </span>
                  <span className="px-2 py-0.5 text-xs rounded-none bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400">
                    {source.count} blocks
                  </span>
                </div>
            {showBar && (
              <div className="flex items-center gap-2 mt-1">
                <span className="text-sm font-medium text-gray-500 w-6" />
                <div className="flex-1 h-1.5 bg-gray-100 dark:bg-charcoal-darkest rounded-none overflow-hidden">
                  <div
                    className="h-full bg-red-500 rounded-none transition-all duration-300"
                    style={{ width: `${barWidth}%` }}
                  />
                </div>
              </div>
            )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
