import { useState, useEffect, useCallback } from 'react'

/**
 * Hook that computes the position for a portal dropdown relative to a trigger element.
 * Automatically calculates whether to render above or below based on available viewport space,
 * and re-positions on scroll and resize.
 *
 * @param {Object} options
 * @param {boolean} options.open - Whether the dropdown is open
 * @param {React.RefObject} options.triggerRef - Ref to the trigger element
 * @param {number} options.estimatedHeight - Estimated dropdown height for above/below calculation
 * @returns {{ top: number, left: number, width: number, positionAbove: boolean }}
 */
export function useDropdownPosition({ open, triggerRef, estimatedHeight = 350 }) {
  const [position, setPosition] = useState({ top: 0, left: 0, width: 0, positionAbove: false })

  const getPosition = useCallback(() => {
    if (!triggerRef.current) return { top: 0, left: 0, width: 0, positionAbove: false }
    const rect = triggerRef.current.getBoundingClientRect()
    const spaceBelow = window.innerHeight - rect.bottom
    const spaceAbove = rect.top
    const positionAbove = spaceBelow < estimatedHeight && spaceAbove > spaceBelow
    return {
      top: positionAbove
        ? rect.top + window.scrollY - estimatedHeight
        : rect.bottom + window.scrollY,
      left: rect.left + window.scrollX,
      width: rect.width,
      positionAbove,
    }
  }, [triggerRef, estimatedHeight])

  // Calculate position when opening
  useEffect(() => {
    if (open) {
      setPosition(getPosition())
    }
  }, [open, getPosition])

  // Re-position on scroll and resize when open
  useEffect(() => {
    if (!open) return
    const updatePosition = () => {
      setPosition(getPosition())
    }
    window.addEventListener('scroll', updatePosition, true)
    window.addEventListener('resize', updatePosition)
    return () => {
      window.removeEventListener('scroll', updatePosition, true)
      window.removeEventListener('resize', updatePosition)
    }
  }, [open, getPosition])

  return position
}

export default useDropdownPosition
