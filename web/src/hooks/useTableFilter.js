import { useMemo } from 'react'

/**
 * Generic hook for filtering and sorting table data.
 *
 * @param {Array} data - The raw data array to filter and sort
 * @param {string} searchTerm - Current search term
 * @param {Object} sortConfig - { key: string, direction: 'asc' | 'desc' }
 * @param {Object} options
 * @param {Function} options.filterFn - Optional custom filter function: (item, searchTerm) => boolean
 * @param {Object} options.fieldMap - Maps sort keys to value extractors: { keyName: (item) => comparableValue }
 * @param {Array} options.extraDeps - Additional dependencies for the useMemo
 * @returns {Array} Filtered and sorted data
 */
export function useTableFilter(data, searchTerm, sortConfig, options = {}) {
  const { filterFn, fieldMap = {}, extraDeps = [], secondarySortKey } = options

  const getValue = (item, key) => {
    if (fieldMap[key]) return fieldMap[key](item)
    return item[key] ?? ''
  }

  return useMemo(() => {
    if (!data) return []

    // Filter
    let filtered = data
    if (searchTerm) {
      const term = searchTerm.toLowerCase()
      if (filterFn) {
        filtered = data.filter(item => filterFn(item, term))
      } else {
        // Default: search all string values in the object
        filtered = data.filter(item =>
          Object.values(item).some(val =>
            typeof val === 'string' && val.toLowerCase().includes(term)
          )
        )
      }
    }

      // Sort
      const sorted = [...filtered].sort((a, b) => {
        let aVal = getValue(a, sortConfig.key)
        let bVal = getValue(b, sortConfig.key)

        // Handle null/undefined values consistently
        if (aVal == null) aVal = ''
        if (bVal == null) bVal = ''

        if (aVal < bVal) return sortConfig.direction === 'asc' ? -1 : 1
        if (aVal > bVal) return sortConfig.direction === 'asc' ? 1 : -1

        // Secondary sort for consistent ordering when primary values are equal
        if (secondarySortKey) {
          const aSecondary = getValue(a, secondarySortKey)
          const bSecondary = getValue(b, secondarySortKey)
          return String(aSecondary).localeCompare(String(bSecondary))
        }

        return 0
      })

    return sorted
    // Spread is intentional to allow flexible additional dependencies
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, searchTerm, sortConfig, filterFn, fieldMap, secondarySortKey, ...extraDeps])
}
