import { Search, X } from 'lucide-react'

/**
 * SearchInput - A search input with icon and clear button.
 *
 * @param {Object} props
 * @param {string} props.value - The current search value
 * @param {Function} props.onChange - Handler called with the new value string
 * @param {Function} [props.onClear] - Handler called when the clear button is clicked
 * @param {string} [props.placeholder='Search...'] - Placeholder text
 * @param {string} [props.ariaLabel='Search'] - Accessible label for the input
 */
export default function SearchInput({ value, onChange, onClear, placeholder = 'Search...', ariaLabel = 'Search' }) {
  return (
    <div className="relative flex-1 max-w-md">
      <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
      <input
        type="text"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label={ariaLabel}
        className="w-full pl-9 pr-10 py-2 border border-gray-300 dark:border-gray-border bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral placeholder-gray-400 focus:ring-2 focus:ring-purple-active focus:border-purple-active rounded-none"
      />
      {value && (
        <button
          onClick={onClear}
          className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-light-neutral"
          aria-label="Clear search"
        >
          <X className="w-4 h-4" />
        </button>
      )}
    </div>
  )
}
