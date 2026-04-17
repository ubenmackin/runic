import { useState, useMemo, useRef, useEffect } from 'react'
import { useAuthStore } from '../store'

export function usePagination(data, pageKey, defaultRowsPerPage = 10) {
  const username = useAuthStore(s => s.username)
  const storageKey = username ? `runic_${username}_${pageKey}_pagination` : null

  const [page, setPage] = useState(1)
  const [rowsPerPage, setRowsPerPageState] = useState(() => {
    if (!storageKey) return defaultRowsPerPage
    const saved = localStorage.getItem(storageKey)
    if (saved) {
      try {
        const parsed = JSON.parse(saved)
        return parsed.rowsPerPage ?? defaultRowsPerPage
      } catch {
        return defaultRowsPerPage
      }
    }
    return defaultRowsPerPage
  })

  useEffect(() => {
    if (storageKey) {
      localStorage.setItem(storageKey, JSON.stringify({ rowsPerPage }))
    }
  }, [storageKey, rowsPerPage])

  // Reset page to 1 when data length changes (e.g., filter reduces results)
  // Using ref to track previous value and setState during render is intentional here
  // for synchronizing pagination with data changes
  const prevDataLengthRef = useRef(data?.length)
  if (prevDataLengthRef.current !== data?.length) {
    prevDataLengthRef.current = data?.length
    if (page !== 1) {
      setPage(1)
    }
  }

  const setRowsPerPage = (newRowsPerPage) => {
    setRowsPerPageState(newRowsPerPage)
    setPage(1)
  }

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
