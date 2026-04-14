import { Outlet } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getVersion } from '../api/client'
import TopNav from './TopNav'
import MobileBottomNav from './MobileBottomNav'

export default function Layout() {
  // Fetch version info
  const { data: versionInfo } = useQuery({
    queryKey: ['version'],
    queryFn: getVersion,
    staleTime: Infinity, // Version doesn't change during session
  })

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-charcoal-darkest flex flex-col">
      {/* Top Navigation */}
      <TopNav />

      {/* Main content */}
      <main className="flex-1 p-4 md:p-6 overflow-auto pb-20 md:pb-6">
        <Outlet />
      </main>

      {/* Footer - hidden on mobile to make room for bottom nav */}
      <footer className="hidden md:block h-10 bg-white dark:bg-charcoal-dark border-t border-gray-200 dark:border-gray-border">
        <div className="flex items-center justify-center h-full">
          <p className="text-gray-400 dark:text-gray-500 text-sm">
            Runic {versionInfo?.version || '...'}
          </p>
        </div>
      </footer>

      {/* Mobile Bottom Navigation */}
      <MobileBottomNav />
    </div>
  )
}
