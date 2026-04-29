export function formatRelativeTime(timestamp) {
  if (!timestamp) return 'Never'
  // Handle SQLite datetime format (YYYY-MM-DD HH:MM:SS) by treating as UTC
  // SQLite's CURRENT_TIMESTAMP and datetime('now') produce UTC times without timezone info
  let normalizedTimestamp = timestamp
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(timestamp)) {
    normalizedTimestamp = timestamp.replace(' ', 'T') + 'Z'
  }
  const date = new Date(normalizedTimestamp)
  const now = new Date()
  const diffMs = now - date
  const diffSeconds = Math.floor(diffMs / 1000)
  const diffMinutes = Math.floor(diffSeconds / 60)
  const diffHours = Math.floor(diffMinutes / 60)
  const diffDays = Math.floor(diffHours / 24)
  if (diffSeconds < 60) return 'Just now'
  if (diffMinutes < 60) return `${diffMinutes} minute${diffMinutes !== 1 ? 's' : ''} ago`
  if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`
  if (diffDays < 7) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`
  return date.toLocaleDateString()
}
