import { useState, useCallback, useRef, useEffect } from 'react'

let toastId = 0

export function useToast() {
  const [toasts, setToasts] = useState([])
  const timersRef = useRef({})

  useEffect(() => {
    return () => {
      Object.values(timersRef.current).forEach(clearTimeout)
      timersRef.current = {}
    }
  }, [])

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
    delete timersRef.current[id]
  }, [])

  const showToast = useCallback((message, type = 'error') => {
    const id = ++toastId
    setToasts((prev) => [...prev, { id, message, type }])
    timersRef.current[id] = setTimeout(() => {
      removeToast(id)
    }, 3000)
  }, [removeToast])

  return { toasts, showToast }
}
