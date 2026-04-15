/**
* @deprecated This component is deprecated and will be removed in v2.0.
* Use SearchFilterPanel instead, which provides enhanced functionality
* and better accessibility support.
*
* Shared FilterBar component for collapsible filter panels.
* Handles expand/collapse state with localStorage persistence.
*
* @param {string} storageKey - Key for localStorage persistence of expand/collapse state
* @param {boolean} hasActiveFilters - Whether any filters are currently active (shows "Active" badge)
* @param {React.ReactNode} children - Filter controls to render when expanded
*/
import { useState } from 'react'
import { Filter, ChevronDown, ChevronUp } from 'lucide-react'
export default function FilterBar({ storageKey, hasActiveFilters, children }) {
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
      {/* Filter toggle */}
      <button
        onClick={handleToggle}
        className="w-full flex items-center justify-between p-4 text-left hover:bg-gray-50 dark:hover:bg-charcoal-darkest transition-colors"
      >
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-500 dark:text-amber-muted" />
          <span className="font-medium text-gray-900 dark:text-light-neutral">Filters</span>
          {hasActiveFilters && (
            <span className="px-2 py-0.5 text-xs bg-purple-active text-white border-0">
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

      {/* Filter options */}
      {expanded && (
        <div className="p-4 pt-0 border-t border-gray-200 dark:border-gray-border">
          <div className="flex flex-wrap gap-4 items-end">
            {children}
          </div>
        </div>
      )}
    </div>
  )
}
