export function formatRelativeTime(timestamp) {
  if (!timestamp) return '—'
  // Handle SQLite datetime format (YYYY-MM-DD HH:MM:SS) by treating as UTC
  // SQLite's CURRENT_TIMESTAMP and datetime('now') produce UTC times without timezone info
  let normalizedTimestamp = timestamp
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(timestamp)) {
    normalizedTimestamp = timestamp.replace(' ', 'T') + 'Z'
  }
  const now = Date.now()
  const then = new Date(normalizedTimestamp).getTime()
  if (isNaN(then)) return '—'
  const diffMs = then - now
  const isFuture = diffMs > 0
  const absDiffMs = Math.abs(diffMs)
  const diffMins = Math.floor(absDiffMs / 60000)
  const diffHours = Math.floor(diffMins / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffMins < 1) return 'Just now'
  if (isFuture) {
    if (diffMins < 60) return `in ${diffMins} min`
    if (diffHours < 24) return `in ${diffHours}h`
    return `in ${diffDays}d`
  }
  if (diffMins < 60) return `${diffMins} min ago`
  if (diffHours < 24) return `${diffHours}h ago`
  return `${diffDays}d ago`
}
