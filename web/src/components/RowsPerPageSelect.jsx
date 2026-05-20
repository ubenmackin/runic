/**
 * RowsPerPageSelect - A dropdown for selecting the number of rows displayed per page.
 *
 * @param {Object} props
 * @param {number} props.value - The currently selected rows-per-page value
 * @param {Function} props.onChange - Handler called with the new numeric value
 */
export default function RowsPerPageSelect({ value, onChange }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(Number(e.target.value))}
      aria-label="Rows per page"
      className="text-xs text-gray-900 dark:text-light-neutral border border-gray-200 dark:border-gray-border bg-white dark:bg-charcoal-dark rounded-none px-2 py-1 focus:outline-none focus:ring-1 focus:ring-purple-active"
    >
      <option value={10}>Rows: 10</option>
      <option value={25}>Rows: 25</option>
      <option value={50}>Rows: 50</option>
      <option value={100}>Rows: 100</option>
      <option value={-1}>Rows: All</option>
    </select>
  )
}
