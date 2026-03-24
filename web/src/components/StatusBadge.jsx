const statusConfig = {
  online:  { dot: 'bg-green-500', text: 'text-green-700 dark:text-green-400', label: 'Online' },
  offline: { dot: 'bg-red-500',   text: 'text-red-700 dark:text-red-400',    label: 'Offline' },
  pending: { dot: 'bg-amber-500',text: 'text-amber-700 dark:text-amber-400', label: 'Pending' },
  error:   { dot: 'bg-red-500',   text: 'text-red-700 dark:text-red-400',    label: 'Error' },
}

export default function StatusBadge({ status }) {
  const config = statusConfig[status] || statusConfig.pending
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${config.text}`}>
      <span className={`w-2 h-2 rounded-full ${config.dot}`} />
      {config.label}
    </span>
  )
}
