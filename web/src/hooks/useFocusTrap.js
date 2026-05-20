import { useEffect, useRef } from 'react'

export function useFocusTrap(modalRef, isOpen) {
  const previousFocusRef = useRef(null)

  useEffect(() => {
    if (!isOpen) {
      // Restore focus to the previously focused element when modal closes
      if (previousFocusRef.current) {
        previousFocusRef.current.focus()
        previousFocusRef.current = null
      }
      return
    }

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
    return () => modal.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, modalRef])
}
