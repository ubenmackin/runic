const colorConfig = {
  synced: 'border-purple-active text-purple-active',
  online: 'border-green-500 text-green-500 dark:text-green-400',
  offline: 'border-red-500 text-red-500 dark:text-red-400',
  pending: 'border-amber-500 text-amber-500 dark:text-amber-400',
  critical: 'border-red-500 text-red-500 dark:text-red-400',
  warning: 'border-amber-500 text-amber-500 dark:text-amber-400',
  info: 'border-blue-500 text-blue-500 dark:text-blue-400',
};

export default function SharpTag({ status, color }) {
  const statusKey = status?.toLowerCase() || 'pending';
  const colorClasses = color || colorConfig[statusKey] || colorConfig.pending;
  const displayStatus = status ? status.toUpperCase() : 'PENDING';

  return (
    <span
      className={`inline-block px-1.5 py-0.5 border font-mono text-[10px] ${colorClasses}`}
    >
      [{displayStatus}]
    </span>
  );
}
