const statusConfig = {
  online: { border: 'border-green-500', text: 'text-green-700 dark:text-green-400', label: 'Online' },
  offline: { border: 'border-red-500', text: 'text-red-700 dark:text-red-400', label: 'Offline' },
  pending: { border: 'border-amber-500', text: 'text-amber-700 dark:text-amber-400', label: 'Pending' },
  error: { border: 'border-red-500', text: 'text-red-700 dark:text-red-400', label: 'Error' },
}

export default function StatusBadge({ status }) {
  const config = statusConfig[status] || statusConfig.pending
  return (
    <span className={`inline-block px-1.5 py-0.5 border font-mono text-[10px] ${config.border} ${config.text}`}>
      [{config.label}]
    </span>
  )
}
