import { useState, useEffect } from 'react'

/**
 * Hook to detect mobile viewport for JS-based conditional rendering.
 * Uses 768px as the default breakpoint (matching Tailwind's `md:`).
 * Handles SSR/hydration by starting with `false` and updating after mount.
 * @param {number} breakpoint - Breakpoint in pixels (default 768)
 * @returns {boolean} True if viewport width is less than the breakpoint
 */
export function useIsMobile(breakpoint = 768) {
  const [isMobile, setIsMobile] = useState(false)

  useEffect(() => {
    const checkIsMobile = () => {
      setIsMobile(window.innerWidth < breakpoint)
    }

    // Check on mount
    checkIsMobile()

    // Check on resize
    window.addEventListener('resize', checkIsMobile)

    return () => window.removeEventListener('resize', checkIsMobile)
  }, [breakpoint])

  return isMobile
}
