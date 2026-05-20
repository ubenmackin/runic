import { useState } from 'react'
import { Search, ChevronDown, ChevronUp } from 'lucide-react'
import SearchInput from './SearchInput'
import RowsPerPageSelect from './RowsPerPageSelect'

/**
 * SearchFilterPanel - Collapsible panel for search and filter controls
 *
 * @param {Object} props
 * @param {string} props.storageKey - Key for storing expansion state in localStorage
 * @param {string} props.searchTerm - Current search term value
 * @param {Function} props.onSearchChange - Handler for search input changes
 * @param {Function} props.onClearSearch - Handler for clearing search
 * @param {string} [props.searchPlaceholder='Search...'] - Placeholder text for search input
 * @param {number} [props.rowsPerPage] - Rows per page count
 * @param {Function} [props.onRowsPerPageChange] - Handler for rows per page changes
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
  rowsPerPage,
  onRowsPerPageChange,
  filterChips,
  children,
  showSearch = true,
  hasActiveFilters = false,
  filterContent,
  rightContent
}) {
  const [expanded, setExpanded] = useState(() => {
    if (!storageKey) return false
    const saved = localStorage.getItem(storageKey)
    return saved === 'true'
  })

  const showRowsPerPageSelect = !rightContent && rowsPerPage !== undefined && onRowsPerPageChange

  const handleToggle = () => {
    const next = !expanded
    setExpanded(next)
    if (storageKey) localStorage.setItem(storageKey, String(next))
  }

  const searchInput = showSearch && (
    <SearchInput
      value={searchTerm}
      onChange={onSearchChange}
      onClear={onClearSearch}
      placeholder={searchPlaceholder}
      ariaLabel="Search"
    />
  )

  const rowsPerPageSelect = showRowsPerPageSelect && (
    <RowsPerPageSelect
      value={rowsPerPage}
      onChange={onRowsPerPageChange}
    />
  )

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
        {searchInput}

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

        {rowsPerPageSelect && (
          <>
            {(filterContent || showSearch) && <div className="flex-grow" />}
            <div className="flex items-center justify-end">
              {rowsPerPageSelect}
            </div>
          </>
        )}
            </div>
          ) : (
        <>
          <div className="flex items-center justify-between gap-4">
            {searchInput}

            {rowsPerPageSelect && (
              <>
                {showSearch && <div className="flex-grow" />}
                <div className="flex items-center justify-end">
                  {rowsPerPageSelect}
                </div>
              </>
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
