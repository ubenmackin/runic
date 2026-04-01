import { useState, useEffect } from 'react'
import { Heart } from 'lucide-react'

function getLastSeen(heartbeat) {
  if (!heartbeat) return 'never'
  const now = new Date()
  const then = new Date(heartbeat)
  const diffMs = now - then
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMins / 60)
  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  return `${Math.floor(diffHours / 24)}d ago`
}

export default function SystemHealth({ peers }) {
  const [currentPage, setCurrentPage] = useState(1)
  const itemsPerPage = 5

  const onlineCount = peers.filter(p => p.is_online && !p.is_manual).length
  const offlineCount = peers.filter(p => !p.is_online && !p.is_manual).length
  const manualCount = peers.filter(p => p.is_manual).length

  // Filter out manual peers from the display list
  const displayPeers = peers.filter(p => !p.is_manual)

  // Sort: offline peers first (alphabetically), then online peers (alphabetically)
  const sortedPeers = [...displayPeers].sort((a, b) => {
    if (a.is_online !== b.is_online) return a.is_online ? 1 : -1 // offline first
    return a.hostname.localeCompare(b.hostname) // then alphabetically
  })

  // Pagination
  const totalPages = Math.ceil(sortedPeers.length / itemsPerPage)
  const startIndex = (currentPage - 1) * itemsPerPage
  const paginatedPeers = sortedPeers.slice(startIndex, startIndex + itemsPerPage)

  // Reset to page 1 if current page exceeds total pages
  useEffect(() => {
    if (currentPage > totalPages && totalPages > 0) {
      setCurrentPage(1)
    }
  }, [currentPage, totalPages])

  return (
    <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm p-4">
      <div className="flex items-center gap-2 mb-4">
        <Heart className="w-5 h-5 text-purple-active" />
        <h3 className="text-sm font-semibold text-gray-900 dark:text-light-neutral">System Health</h3>
      </div>

      {/* Summary Bar */}
      <div className="flex flex-wrap gap-2 mb-4">
        <span className="px-2 py-1 text-xs font-medium rounded-full bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400">
          🟢 {onlineCount} Online
        </span>
        <span className="px-2 py-1 text-xs font-medium rounded-full bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400">
          🔴 {offlineCount} Offline
        </span>
        <span className="px-2 py-1 text-xs font-medium rounded-full bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400">
          📋 {manualCount} Manual
        </span>
      </div>

      {sortedPeers.length === 0 ? (
        <p className="text-sm text-gray-400 dark:text-amber-muted text-center py-4">
          No peers registered
        </p>
      ) : (
        <>
          <div className="space-y-0">
        {paginatedPeers.map((peer) => (
          <div key={peer.hostname} className="flex items-center gap-2 py-2 border-b border-gray-100 dark:border-gray-border last:border-0">
                {/* Status dot */}
                <div className={`w-2 h-2 rounded-full shrink-0 ${peer.is_online ? 'bg-green-500' : 'bg-gray-400'}`} />

                {/* Hostname */}
                <span className="font-medium text-gray-900 dark:text-light-neutral">
                  {peer.hostname}
                </span>

                {/* IP and version info */}
                <div className="flex flex-col">
                  <span className="text-xs text-gray-500 dark:text-amber-muted ml-4">
                    {peer.ip_address}
                  </span>
                  {peer.is_online && peer.agent_version && (
                    <span className="text-xs text-gray-400 ml-4">
                      v{peer.agent_version}
                    </span>
                  )}
                  {!peer.is_online && (
                    <span className="text-xs text-red-500 ml-4">
                      last seen {getLastSeen(peer.last_heartbeat)}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* Pagination controls */}
          {totalPages > 1 && (
            <div className="flex justify-center gap-2 mt-3 pt-3 border-t border-gray-100 dark:border-gray-border">
        <button
          onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
          disabled={currentPage === 1}
          aria-label="Previous page"
          className="px-3 py-1 text-xs rounded bg-gray-100 dark:bg-gray-700 disabled:opacity-50"
        >
          Prev
        </button>
              <span className="text-xs text-gray-500 dark:text-amber-muted">
                {currentPage} / {totalPages}
              </span>
        <button
          onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
          disabled={currentPage === totalPages}
          aria-label="Next page"
          className="px-3 py-1 text-xs rounded bg-gray-100 dark:bg-gray-700 disabled:opacity-50"
        >
          Next
        </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
