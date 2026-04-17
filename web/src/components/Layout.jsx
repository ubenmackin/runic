import { Outlet } from 'react-router-dom'
import TopNav from './TopNav'
import MobileBottomNav from './MobileBottomNav'

export default function Layout() {
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-charcoal-darkest flex flex-col">
      <TopNav />

      <main className="flex-1 p-4 md:p-6 overflow-auto pb-20 md:pb-6">
        <Outlet />
      </main>

      <MobileBottomNav />
    </div>
  )
}
