import { useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'

export default function LogLine({ log, expanded, onToggle }) {
  const isControlled = expanded !== undefined
  const [isExpanded, setIsExpanded] = useState(false)
  const showExpanded = isControlled ? expanded : isExpanded

  const toggleExpand = () => {
    if (isControlled) {
      if (onToggle) onToggle(log.id)
    } else {
      setIsExpanded(!isExpanded)
      if (onToggle) onToggle(log.id)
    }
  }

  const actionColor = log.action === 'DROP' || log.action === 'BLOCK'
    ? 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300'
    : 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300'

  const directionIcon = log.direction === 'IN' ? '↓' : '↑'
  const directionColor = log.direction === 'IN'
    ? 'text-blue-600 dark:text-blue-400'
    : 'text-amber-600 dark:text-amber-400'

  return (
    <div className="border-b border-gray-200 dark:border-gray-border">
      <div
        className="flex items-center gap-2 px-3 py-2 hover:bg-gray-50 dark:hover:bg-charcoal-dark cursor-pointer font-mono text-xs"
        onClick={toggleExpand}
      >
        {/* Expand toggle */}
        <button className="p-0.5 hover:bg-gray-200 dark:hover:bg-charcoal-darkest rounded">
          {showExpanded ? (
            <ChevronDown className="w-3 h-3 text-gray-400" />
          ) : (
            <ChevronRight className="w-3 h-3 text-gray-400" />
          )}
        </button>

        {/* Timestamp */}
        <span className="text-gray-500 dark:text-amber-muted w-36 whitespace-nowrap">
          {log.timestamp?.replace('T', ' ').slice(0, 19) || '—'}
        </span>

        {/* Action badge */}
        <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${actionColor}`}>
          {log.action}
        </span>

        {/* Direction */}
        <span className={`font-bold ${directionColor}`}>
          {directionIcon}
        </span>

        {/* Source */}
<span className="text-gray-700 dark:text-amber-primary">
{log.src_ip}
          {log.src_port ? `:${log.src_port}` : ''}
        </span>

        {/* Arrow */}
        <span className="text-gray-400">→</span>

        {/* Destination */}
<span className="text-gray-700 dark:text-amber-primary">
{log.dst_ip}
          {log.dst_port ? `:${log.dst_port}` : ''}
        </span>

        {/* Protocol */}
        <span className="text-gray-500 dark:text-amber-muted uppercase">
          {log.protocol}
        </span>
      </div>

      {/* Expanded raw line */}
      {showExpanded && (
        <div className="px-3 py-2 bg-gray-50 dark:bg-charcoal-darkest text-xs">
          <div className="mb-1 font-medium text-gray-700 dark:text-amber-primary">
            Raw Kernel Log:
          </div>
          <pre className="text-gray-600 dark:text-amber-muted whitespace-pre-wrap break-all font-mono">
            {log.raw_line || 'No raw log available'}
          </pre>
          {log.hostname && (
            <div className="mt-2 text-gray-500 dark:text-amber-muted">
              Server: {log.hostname}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
