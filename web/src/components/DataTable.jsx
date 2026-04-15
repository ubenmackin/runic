import { ChevronLeft, ChevronRight } from 'lucide-react'

export default function DataTable({ columns, data, emptyMessage, onRowClick, pagination }) {
  const { page, rowsPerPage, totalItems, onPageChange, onRowsPerPageChange, showingRange } = pagination || {}

// Rows per page options
const rowsOptions = [10, 25, 50, 100, -1]

const totalPages = rowsPerPage === -1 ? 1 : Math.ceil(totalItems / rowsPerPage)
  const canGoPrev = page > 1
  const canGoNext = page < totalPages

  if (!data?.length) {
    return emptyMessage ? <p className="text-gray-500 text-sm py-4">{emptyMessage}</p> : null
  }

  return (
    <div className="bg-white dark:bg-charcoal-dark shadow-none overflow-hidden">
      {/* Rows per page dropdown - top right */}
      {pagination && (
        <div className="flex justify-end items-center gap-2 px-4 py-3 border-b border-gray-200 dark:border-gray-border">
          <span className="text-sm text-gray-500 dark:text-amber-muted">Rows per page:</span>
          <select
            value={rowsPerPage}
            onChange={(e) => onRowsPerPageChange(Number(e.target.value))}
            className="text-sm border border-gray-300 dark:border-gray-border rounded-none px-2 py-1 bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral focus:ring-2 focus:ring-purple-active focus:border-purple-active"
            aria-label="Rows per page"
          >
            {rowsOptions.map(opt => (
              <option key={opt} value={opt}>
                {opt === -1 ? 'All' : opt}
              </option>
            ))}
          </select>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
<thead className="bg-gray-50 dark:bg-charcoal-darkest border-b border-gray-200 dark:border-gray-border">
          <tr>
            {columns.map(col => (
              <th key={col.key} className={`text-left px-4 py-1 font-medium text-slate-500 text-[10px] uppercase tracking-wider ${col.className || ''}`}>
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-border">
            {data.map((item, idx) => (
              <tr 
                key={item.id ?? idx}
                className={`${onRowClick ? 'cursor-pointer' : ''}`}
                onClick={onRowClick ? () => onRowClick(item) : undefined}
              >
                {columns.map(col => (
<td key={col.key} className={`px-4 py-1 ${col.cellClassName || ''}`}>
                  {col.render ? col.render(item) : item[col.key]}
                </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination controls - below table */}
      {pagination && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 dark:border-gray-border bg-gray-50 dark:bg-charcoal-darkest">
          <span className="text-sm text-gray-500 dark:text-amber-muted">
            {showingRange}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => onPageChange(page - 1)}
              disabled={!canGoPrev}
              className="p-1.5 rounded-none hover:bg-gray-200 dark:hover:bg-charcoal-dark disabled:opacity-40 disabled:cursor-not-allowed"
              title="Previous page"
              aria-label="Go to previous page"
            >
              <ChevronLeft className="w-5 h-5 text-gray-600 dark:text-amber-primary" />
            </button>
            {/* Page numbers */}
            {totalPages <= 7 ? (
              // Show all pages if 7 or fewer
              Array.from({ length: totalPages }, (_, i) => i + 1).map(p => (
                <button
                  key={p}
                  onClick={() => onPageChange(p)}
                  className={`min-w-[32px] h-8 px-2 rounded-none text-sm ${
                    p === page
                      ? 'bg-purple-active text-white'
                      : 'hover:bg-gray-200 dark:hover:bg-charcoal-dark text-gray-700 dark:text-amber-primary'
                  }`}
                  aria-label={`Go to page ${p}`}
                >
                  {p}
                </button>
              ))
            ) : (
              // Show ellipsis for many pages
              <>
                {/* First page */}
                <button
                  onClick={() => onPageChange(1)}
                  className={`min-w-[32px] h-8 px-2 rounded-none text-sm ${
                    1 === page
                      ? 'bg-purple-active text-white'
                      : 'hover:bg-gray-200 dark:hover:bg-charcoal-dark text-gray-700 dark:text-amber-primary'
                  }`}
                  aria-label="Go to page 1"
                >
                  1
                </button>
                
                {/* Ellipsis or second page */}
                {page > 3 ? (
                  <span className="px-1 text-gray-400">...</span>
                ) : page === 3 ? (
                  <button
                    onClick={() => onPageChange(2)}
                    className="min-w-[32px] h-8 px-2 rounded-none text-sm hover:bg-gray-200 dark:hover:bg-charcoal-dark text-gray-700 dark:text-amber-primary"
                    aria-label="Go to page 2"
                  >
                    2
                  </button>
                ) : null}

                {/* Middle pages */}
                {page > 2 && page < totalPages - 1 && (
                  <button
                    onClick={() => onPageChange(page)}
                    className="min-w-[32px] h-8 px-2 rounded text-sm bg-purple-active text-white"
                    aria-label={`Go to page ${page}`}
                  >
                    {page}
                  </button>
                )}

                {/* Ellipsis or second-to-last page */}
                {page < totalPages - 2 ? (
                  <span className="px-1 text-gray-400">...</span>
                ) : page === totalPages - 2 ? (
                  <button
                    onClick={() => onPageChange(totalPages - 1)}
                    className="min-w-[32px] h-8 px-2 rounded-none text-sm hover:bg-gray-200 dark:hover:bg-charcoal-dark text-gray-700 dark:text-amber-primary"
                    aria-label={`Go to page ${totalPages - 1}`}
                  >
                    {totalPages - 1}
                  </button>
                ) : null}

                {/* Last page */}
                {totalPages > 1 && (
                  <button
                    onClick={() => onPageChange(totalPages)}
                    className={`min-w-[32px] h-8 px-2 rounded-none text-sm ${
                      totalPages === page
                        ? 'bg-purple-active text-white'
                        : 'hover:bg-gray-200 dark:hover:bg-charcoal-dark text-gray-700 dark:text-amber-primary'
                    }`}
                    aria-label={`Go to page ${totalPages}`}
                  >
                    {totalPages}
                  </button>
                )}
              </>
            )}
            <button
              onClick={() => onPageChange(page + 1)}
              disabled={!canGoNext}
              className="p-1.5 rounded-none hover:bg-gray-200 dark:hover:bg-charcoal-dark disabled:opacity-40 disabled:cursor-not-allowed"
              title="Next page"
              aria-label="Go to next page"
            >
              <ChevronRight className="w-5 h-5 text-gray-600 dark:text-amber-primary" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
