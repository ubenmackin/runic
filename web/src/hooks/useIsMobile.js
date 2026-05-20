import { useState, useEffect } from 'react'

/**
 * Hook to detect mobile viewport for JS-based conditional rendering.
 * Uses 768px as the default breakpoint (matching Tailwind's `md:`).
 * Uses matchMedia for performant, event-driven breakpoint detection.
 * Handles SSR/hydration by starting with `false` and updating after mount.
 * @param {number} breakpoint - Breakpoint in pixels (default 768)
 * @returns {boolean} True if viewport width is less than the breakpoint
 */
export function useIsMobile(breakpoint = 768) {
  const [isMobile, setIsMobile] = useState(false)

  useEffect(() => {
    const mql = window.matchMedia(`(max-width: ${breakpoint - 1}px)`)

    const handleChange = (e) => {
      setIsMobile(e.matches)
    }

    // Set initial value
    setIsMobile(mql.matches)

    // Listen for changes
    mql.addEventListener('change', handleChange)

    return () => mql.removeEventListener('change', handleChange)
  }, [breakpoint])

  return isMobile
}
