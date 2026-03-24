import { useState, useCallback, useRef } from 'react'

export function useToast() {
  const [toast, setToast] = useState(null)
  const timeoutRef = useRef(null)

  const showToast = useCallback((message, type = 'error') => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current)
    setToast({ message, type })
    timeoutRef.current = setTimeout(() => {
      setToast(null)
      timeoutRef.current = null
    }, 3000)
  }, [])

  return { toast, showToast }
}
