const colorConfig = {
  // Peer sync status colors (used by Peers.jsx)
  synced: 'border-green-500 text-green-600 dark:text-green-400',
  review: 'border-orange-500 text-orange-600 dark:text-orange-400',
  pending_sync: 'border-blue-500 text-blue-600 dark:text-blue-400',
  online: 'border-green-500 text-green-500 dark:text-green-400',
  offline: 'border-red-500 text-red-500 dark:text-red-400',
  pending: 'border-amber-500 text-amber-500 dark:text-amber-400',
  critical: 'border-red-500 text-red-500 dark:text-red-400',
  warning: 'border-amber-500 text-amber-500 dark:text-amber-400',
  info: 'border-blue-500 text-blue-500 dark:text-blue-400',
};

/**
 * SharpTag - A styled status tag component
 * @param {string} status - The status key for color lookup (will be uppercased for display if label not provided)
 * @param {string} [label] - Optional custom label text (preserves original casing, e.g., group names)
 * @param {string} [variant='default'] - Display variant: 'default' (bracketed [STATUS]) or 'badge' (plain text)
 * @param {string} [color] - Optional color classes to override the default based on status
 */
export default function SharpTag({ status, label, variant = 'default', color }) {
  const statusKey = status?.toLowerCase() || 'pending';
  const colorClasses = color || colorConfig[statusKey] || colorConfig.pending;
  const displayText = label ?? (status ? status.toUpperCase() : 'PENDING');

  if (variant === 'default') {
    return (
      <span
        className={`inline-block px-1.5 py-0.5 border font-mono text-[10px] ${colorClasses}`}
      >
        [{displayText}]
      </span>
    );
  }

  return (
    <span
      className={`inline-block px-1.5 py-0.5 border text-xs font-medium ${colorClasses}`}
    >
      {displayText}
    </span>
  );
}
