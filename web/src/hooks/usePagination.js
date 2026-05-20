import { useState, useMemo, useRef, useEffect, useCallback } from 'react'
import { useLocalStorage } from './useLocalStorage'
import { useCurrentUsername, buildStorageKey } from './useCurrentUsername'

export function usePagination(data, pageKey, defaultRowsPerPage = 10) {
  const username = useCurrentUsername()
  const storageKey = buildStorageKey(username, pageKey, 'pagination')
  const [rowsPerPage, setRowsPerPageState] = useLocalStorage(
    storageKey,
    defaultRowsPerPage,
    300,
    (saved) => {
      // Migration: old format stored { rowsPerPage: N }, new format stores just N
      if (saved && typeof saved === 'object' && 'rowsPerPage' in saved) {
        return saved.rowsPerPage
      }
      return saved
    }
  )

  const [page, setPage] = useState(1)

  // Reset page to 1 when data length changes (batched with same render)
  const prevDataLengthRef = useRef(data?.length)
  useEffect(() => {
    if (prevDataLengthRef.current !== data?.length) {
      prevDataLengthRef.current = data?.length
      setPage(1)
    }
  }, [data?.length])

  const setRowsPerPage = useCallback((newRowsPerPage) => {
    setRowsPerPageState(newRowsPerPage)
    setPage(1)
  }, [setRowsPerPageState])

  const paginatedData = useMemo(() => {
    if (!data) return []
    if (rowsPerPage === -1) return data // "All" - no pagination

    const startIndex = (page - 1) * rowsPerPage
    const endIndex = startIndex + rowsPerPage
    return data.slice(startIndex, endIndex)
  }, [data, page, rowsPerPage])

  const totalItems = data?.length || 0
  const totalPages = rowsPerPage === -1 ? 1 : Math.ceil(totalItems / rowsPerPage)

  const startIndex = totalItems === 0 ? 0 : (page - 1) * (rowsPerPage || 10) + 1
  const endIndex = rowsPerPage === -1 ? totalItems : Math.min(page * (rowsPerPage || 10), totalItems)

  const showingRange = rowsPerPage === -1
    ? `Showing all ${totalItems}`
    : `Showing ${startIndex}-${endIndex} of ${totalItems}`

  return {
    paginatedData,
    totalPages,
    startIndex,
    endIndex,
    showingRange,
    page,
    rowsPerPage,
    onPageChange: setPage,
    onRowsPerPageChange: setRowsPerPage,
    totalItems
  }
}
