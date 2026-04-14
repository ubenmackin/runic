import { Search } from 'lucide-react'

export default function TableToolbar({
  searchTerm,
  onSearchChange,
  onClearSearch,
  placeholder = 'Search...',
  rowsPerPage,
  onRowsPerPageChange,
  children,
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div className="relative flex-1 max-w-md">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
        <input
          type="text"
          placeholder={placeholder}
          value={searchTerm}
          onChange={(e) => onSearchChange(e.target.value)}
          className="w-full pl-9 pr-10 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral placeholder-gray-400 focus:ring-2 focus:ring-purple-active focus:border-purple-active"
        />
        {searchTerm && (
          <button
            onClick={onClearSearch}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-light-neutral"
            aria-label="Clear search"
          >
            ×
          </button>
        )}
      </div>
      <div className="flex items-center gap-2">
        <span className="text-sm text-gray-500 dark:text-amber-muted">Rows:</span>
        <select
          value={rowsPerPage}
          onChange={(e) => onRowsPerPageChange(Number(e.target.value))}
          className="text-sm border border-gray-300 dark:border-gray-border rounded-none px-2 py-2 bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral focus:ring-2 focus:ring-purple-active focus:border-purple-active"
        >
          <option value={10}>10</option>
          <option value={25}>25</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
          <option value={-1}>All</option>
        </select>
      </div>
      {children}
    </div>
  )
}
