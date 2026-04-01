import { ChevronLeft, ChevronRight } from 'lucide-react'

export default function Pagination({ showingRange, page, totalPages, onPageChange, totalItems }) {
  if (!totalItems || totalItems <= 0) return null

  return (
    <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 dark:border-gray-border bg-gray-50 dark:bg-charcoal-darkest">
      <span className="text-sm text-gray-500 dark:text-amber-muted">
        {showingRange}
      </span>
      <div className="flex items-center gap-1">
        <button
          onClick={() => onPageChange(page - 1)}
          disabled={page <= 1}
          className="p-1.5 rounded hover:bg-gray-200 dark:hover:bg-charcoal-dark disabled:opacity-40 disabled:cursor-not-allowed"
          title="Previous page"
          aria-label="Previous page"
        >
          <ChevronLeft className="w-5 h-5 text-gray-600 dark:text-amber-primary" />
        </button>
        <span className="px-3 text-sm text-gray-600 dark:text-amber-primary">
          Page {page} of {totalPages}
        </span>
        <button
          onClick={() => onPageChange(page + 1)}
          disabled={page >= totalPages}
          className="p-1.5 rounded hover:bg-gray-200 dark:hover:bg-charcoal-dark disabled:opacity-40 disabled:cursor-not-allowed"
          title="Next page"
          aria-label="Next page"
        >
          <ChevronRight className="w-5 h-5 text-gray-600 dark:text-amber-primary" />
        </button>
      </div>
    </div>
  )
}
