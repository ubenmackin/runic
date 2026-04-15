import { useState } from 'react'
import { Search, ChevronDown, ChevronUp } from 'lucide-react'

export default function SearchFilterPanel({
  storageKey,
  searchTerm,
  onSearchChange,
  onClearSearch,
  searchPlaceholder = 'Search...',
  rowsPerPage,
  onRowsPerPageChange,
  filterChips, // React node for filter buttons/chips
  children, // Additional content (e.g., pending delete toggle)
  showSearch = true, // Whether to show the search input
  hasActiveFilters = false, // Whether any filters are currently active (shows "Active" badge)
  filterContent, // Inline filters for horizontal layout (left side)
  rightContent // Right-aligned content (e.g., Rows dropdown)
}) {
  const [expanded, setExpanded] = useState(() => {
    const saved = localStorage.getItem(storageKey)
    return saved === null ? true : saved === 'true' // Default open
  })

  const handleToggle = () => {
    const next = !expanded
    setExpanded(next)
    localStorage.setItem(storageKey, String(next))
  }

  return (
    <div className="bg-white dark:bg-charcoal-dark border border-gray-200 dark:border-gray-border overflow-hidden">
      {/* Toggle header */}
      <button
        onClick={handleToggle}
        aria-expanded={expanded}
        className="w-full flex items-center justify-between p-4 text-left hover:bg-gray-50 dark:hover:bg-charcoal-darkest transition-colors"
      >
      <div className="flex items-center gap-2">
        <Search className="w-4 h-4 text-gray-500 dark:text-amber-muted" />
        <span className="font-medium text-gray-900 dark:text-light-neutral">{showSearch ? 'Search & Filters' : 'Filters'}</span>
        {hasActiveFilters && (
          <span className="px-2 py-0.5 text-xs font-medium bg-purple-active text-white rounded-full">
            Active
          </span>
        )}
      </div>
        {expanded ? (
          <ChevronUp className="w-4 h-4 text-gray-500 dark:text-amber-muted" />
        ) : (
          <ChevronDown className="w-4 h-4 text-gray-500 dark:text-amber-muted" />
        )}
      </button>

{/* Content */}
      {expanded && (
        <div className="p-4 border-t border-gray-200 dark:border-gray-border space-y-3">
          {/* Horizontal layout when filterContent or rightContent is provided */}
          {(filterContent || rightContent) ? (
            <div className="flex items-center gap-4">
              {/* Search input */}
              {showSearch && (
                <div className="relative flex-1 max-w-md">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
                  <input
                    type="text"
                    placeholder={searchPlaceholder}
                    value={searchTerm}
                    onChange={(e) => onSearchChange(e.target.value)}
                    className="w-full pl-9 pr-10 py-2 border border-gray-300 dark:border-gray-border bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral placeholder-gray-400 focus:ring-2 focus:ring-purple-active focus:border-purple-active rounded-none"
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
              )}

              {/* Inline filter content (left side) */}
              {filterContent && (
                <div className={showSearch ? '' : 'flex-1'}>
                  {filterContent}
                </div>
              )}

              {/* Spacer to push rightContent to far right */}
              {(filterContent || showSearch) && rightContent && (
                <div className="flex-grow" />
              )}

              {/* Right-aligned content */}
              {rightContent && (
                <div className="flex items-center">
                  {rightContent}
                </div>
              )}
            </div>
          ) : (
            /* Default vertical layout (backwards compatibility) */
            <>
              {/* Search row */}
              <div className="flex items-center justify-between gap-4">
                {showSearch && (
                  <div className="relative flex-1 max-w-md">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
                    <input
                      type="text"
                      placeholder={searchPlaceholder}
                      value={searchTerm}
                      onChange={(e) => onSearchChange(e.target.value)}
                      className="w-full pl-9 pr-10 py-2 border border-gray-300 dark:border-gray-border bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral placeholder-gray-400 focus:ring-2 focus:ring-purple-active focus:border-purple-active rounded-none"
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
                )}

                <div className="flex items-center gap-2">
                  <span className="text-sm text-gray-500 dark:text-amber-muted">Rows:</span>
                  <select
                    value={rowsPerPage}
                    onChange={(e) => onRowsPerPageChange(Number(e.target.value))}
                    className="text-sm border border-gray-300 dark:border-gray-border px-2 py-2 bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral focus:ring-2 focus:ring-purple-active focus:border-purple-active rounded-none"
                  >
                    <option value={10}>10</option>
                    <option value={25}>25</option>
                    <option value={50}>50</option>
                    <option value={100}>100</option>
                    <option value={-1}>All</option>
                  </select>
                </div>
              </div>

              {/* Filter chips row */}
              {filterChips && (
                <div className="flex gap-0">
                  {filterChips}
                </div>
              )}
            </>
          )}

          {/* Additional content (e.g., pending delete toggle) - rendered below main content */}
          {children}
        </div>
      )}
    </div>
  )
}
