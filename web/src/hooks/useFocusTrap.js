import { useEffect, useRef } from 'react'

export function useFocusTrap(modalRef, isOpen) {
  const previousFocusRef = useRef(null)

  useEffect(() => {
    if (!isOpen) return

    // Save the currently focused element before opening
    previousFocusRef.current = document.activeElement

    const modal = modalRef.current
    if (!modal) {
      previousFocusRef.current = null
      return
    }

    const focusableElements = modal.querySelectorAll(
      'button, [href], input, select, textarea, [contenteditable], [tabindex]:not([tabindex="-1"])'
    )
    const firstElement = focusableElements[0]
    const lastElement = focusableElements[focusableElements.length - 1]

    firstElement?.focus()

    const handleKeyDown = (e) => {
      if (e.key === 'Tab') {
        if (e.shiftKey && document.activeElement === firstElement) {
          e.preventDefault()
          lastElement?.focus()
        } else if (!e.shiftKey && document.activeElement === lastElement) {
          e.preventDefault()
          firstElement?.focus()
        }
      }
    }

    modal.addEventListener('keydown', handleKeyDown)

    return () => {
      modal.removeEventListener('keydown', handleKeyDown)
      // Restore focus on cleanup — fires on both isOpen->false transitions
      // AND when a modal is conditionally unmounted from the DOM.
      if (previousFocusRef.current) {
        previousFocusRef.current.focus()
        previousFocusRef.current = null
      }
    }
  }, [isOpen, modalRef])
}
