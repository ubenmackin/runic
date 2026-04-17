import { useState } from 'react'
import { Search, ChevronDown, ChevronUp, X } from 'lucide-react'

/**
 * SearchFilterPanel - Collapsible panel for search and filter controls
 *
 * @param {Object} props
 * @param {string} props.storageKey - Key for storing expansion state in localStorage
 * @param {string} props.searchTerm - Current search term value
 * @param {Function} props.onSearchChange - Handler for search input changes
 * @param {Function} props.onClearSearch - Handler for clearing search
 * @param {string} [props.searchPlaceholder='Search...'] - Placeholder text for search input
 * @param {number} [props.rowsPerPage] - (Intentionally unused) Reserved for interface compatibility
 * @param {Function} [props.onRowsPerPageChange] - (Intentionally unused) Reserved for interface compatibility
 * @param {React.ReactNode} [props.filterChips] - React node for filter buttons/chips
 * @param {React.ReactNode} [props.children] - Additional content rendered below main content
 * @param {boolean} [props.showSearch=true] - Whether to show the search input
 * @param {boolean} [props.hasActiveFilters=false] - Whether filters are active (shows badge)
 * @param {React.ReactNode} [props.filterContent] - Inline filters for horizontal layout (left side). When provided, enables horizontal flex layout.
 * @param {React.ReactNode} [props.rightContent] - Right-aligned content (e.g., action buttons). Rendered on far right with flex spacer.
 */
export default function SearchFilterPanel({
  storageKey,
  searchTerm,
  onSearchChange,
  onClearSearch,
  searchPlaceholder = 'Search...',
  _rowsPerPage,
  _onRowsPerPageChange,
  filterChips,
  children,
  showSearch = true,
  hasActiveFilters = false,
  filterContent,
  rightContent
}) {
  const [expanded, setExpanded] = useState(() => {
    const saved = localStorage.getItem(storageKey)
    return saved === 'true'
  })

  const handleToggle = () => {
    const next = !expanded
    setExpanded(next)
    localStorage.setItem(storageKey, String(next))
  }

  return (
    <div className="bg-white dark:bg-charcoal-dark border border-gray-200 dark:border-gray-border overflow-hidden">
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

      {expanded && (
        <div className="p-4 border-t border-gray-200 dark:border-gray-border space-y-3">
          {(filterContent || rightContent) ? (
            <div className="flex items-center gap-4">
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
            <X className="w-4 h-4" />
          </button>
        )}
                </div>
              )}

              {filterContent && (
                <div className={showSearch ? '' : 'flex-1'}>
                  {filterContent}
                </div>
              )}

              {(filterContent || showSearch) && rightContent && (
                <div className="flex-grow" />
              )}

        {rightContent && (
          <div className="flex items-center justify-end">
            {rightContent}
          </div>
        )}
            </div>
          ) : (
            <>
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
  <X className="w-4 h-4" />
</button>
                    )}
                  </div>
          )}
        </div>

              {filterChips && (
                <div className="flex gap-0">
                  {filterChips}
                </div>
              )}
            </>
          )}

          {children}
        </div>
      )}
    </div>
  )
}
