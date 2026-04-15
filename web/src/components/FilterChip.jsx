/**
 * A clickable filter button for toggling filter states.
 *
 * Note: This component uses larger sizing (px-4 py-1.5 text-sm font-medium) compared to
 * badges (px-2 py-0.5 text-xs). This difference is intentional:
 * - FilterChip: Larger for better touch target accessibility (clickable filter buttons)
 * - Badges: Smaller for inline labels and status indicators
 *
 * Use FilterChip when you need interactive filter buttons that users will click.
 * Use SharpTag with variant='badge' for static labels and status indicators.
 */
export default function FilterChip({ label, selected, onClick }) {
  return (
    <button
      onClick={onClick}
      aria-pressed={selected}
      aria-label={label}
      className={`px-4 py-1.5 text-sm font-medium border transition-colors ${
        selected
          ? 'bg-purple-active text-white border-purple-active'
          : 'bg-white dark:bg-charcoal-dark text-gray-700 dark:text-light-neutral border-gray-300 dark:border-gray-border hover:bg-gray-50 dark:hover:bg-charcoal-darkest'
      }`}
    >
      {label}
    </button>
  )
}
