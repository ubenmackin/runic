import { useState, useEffect, useRef, useId } from 'react'
import { ChevronDown } from 'lucide-react'

/**
 * CollapsibleSection - A reusable collapsible section with animation and localStorage persistence
 *
 * @param {Object} props
 * @param {string} props.title - Section title
 * @param {React.ReactNode} [props.icon] - Optional icon to display before title
 * @param {boolean} [props.defaultExpanded=false] - Initial expanded state (uncontrolled mode)
 * @param {boolean} [props.expanded] - Controlled expanded state
 * @param {function} [props.onExpandedChange] - Callback when expanded state changes (controlled mode)
 * @param {string} [props.storageKey] - localStorage key for persistence
 * @param {string|React.ReactNode} [props.summary] - Badge or summary shown when collapsed
 * @param {React.ReactNode} props.children - Content to show when expanded
 * @param {string} [props.className] - Additional CSS classes
 * @param {string} [props.id] - Optional ID for the section wrapper (for anchor navigation)
 */
export default function CollapsibleSection({
  title,
  icon,
  defaultExpanded = false,
  expanded: controlledExpanded,
  onExpandedChange,
  storageKey,
  summary,
  children,
  className = '',
  id,
}) {
  const contentRef = useRef(null)
  const headerId = useId()
  const contentId = useId()

  // Determine if component is controlled
  const isControlled = controlledExpanded !== undefined

  // Initialize state with localStorage persistence if storageKey provided
  const [internalExpanded, setInternalExpanded] = useState(() => {
    if (isControlled) return controlledExpanded
    if (storageKey) {
      try {
        const saved = localStorage.getItem(storageKey)
        if (saved !== null) {
          return JSON.parse(saved)
        }
      } catch {
        // Ignore parse errors
      }
    }
    return defaultExpanded
  })

  // Use controlled value if provided, otherwise internal state
  const expanded = isControlled ? controlledExpanded : internalExpanded

  // Sync with localStorage when storageKey changes (also sync on mount)
  useEffect(() => {
    if (storageKey && !isControlled) {
      localStorage.setItem(storageKey, JSON.stringify(expanded))
    }
  }, [storageKey, expanded, isControlled])

  // Handle toggle
  const handleToggle = () => {
    if (isControlled) {
      onExpandedChange?.(!expanded)
    } else {
      setInternalExpanded(!expanded)
      onExpandedChange?.(!expanded)
    }
  }

  // Keyboard handler
  const handleKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      handleToggle()
    }
  }

  // Calculate content height for animation
  const contentHeight = contentRef.current?.scrollHeight || 0

  return (
    <div
      id={id}
      className={`border border-gray-200 dark:border-gray-border bg-white dark:bg-charcoal-dark ${className}`}
    >
      {/* Header */}
      <button
        type="button"
        id={headerId}
        aria-expanded={expanded}
        aria-controls={contentId}
        onClick={handleToggle}
        onKeyDown={handleKeyDown}
        className={`
          w-full flex items-center justify-between px-4 py-3
          text-left hover:bg-gray-50 dark:hover:bg-charcoal-darkest
          focus:outline-none focus:ring-2 focus:ring-purple-active focus:ring-inset
          transition-colors duration-150
        `}
      >
        <div className="flex items-center gap-3">
          {icon && (
            <span className="flex-shrink-0 text-gray-500 dark:text-amber-muted">
              {icon}
            </span>
          )}
          <span className="text-sm font-medium text-gray-900 dark:text-light-neutral">
            {title}
          </span>
          {!expanded && summary && (
            <span className="ml-2 text-xs text-gray-500 dark:text-amber-muted">
              {summary}
            </span>
          )}
        </div>
        <ChevronDown
          className={`
            w-5 h-5 text-gray-400 dark:text-amber-muted
            transition-transform duration-200 ease-in-out
            ${expanded ? 'rotate-180' : ''}
          `}
        />
      </button>

      {/* Content with height animation */}
      <div
        id={contentId}
        role="region"
        aria-labelledby={headerId}
        style={{
          maxHeight: expanded ? `${contentHeight}px` : '0',
          overflow: 'hidden',
          transition: 'max-height 200ms ease-in-out',
        }}
      >
        <div
          ref={contentRef}
          className={`
            px-4 py-3 border-t border-gray-200 dark:border-gray-border
            transition-opacity duration-200
            ${expanded ? 'opacity-100' : 'opacity-0'}
          `}
        >
          {children}
        </div>
      </div>
    </div>
  )
}
