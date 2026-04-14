import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Network, Shield, FileText, Settings } from 'lucide-react'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/topology', icon: Network, label: 'Topology' },
  { to: '/peers', icon: Shield, label: 'Access Control' },
  { to: '/logs', icon: FileText, label: 'Logs' },
  { to: '/settings', icon: Settings, label: 'Settings' },
]

export default function MobileBottomNav() {
  return (
    <nav className="fixed bottom-0 left-0 right-0 h-16 bg-charcoal-dark border-t border-gray-border md:hidden">
      <div className="flex items-center justify-around h-full">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            className={({ isActive }) =>
              `flex flex-col items-center justify-center px-3 py-2 transition-colors ${
                isActive
                  ? 'text-purple-active'
                  : 'text-gray-400 hover:text-light-neutral'
              }`
            }
          >
            <item.icon className="w-5 h-5" />
            <span className="text-xs mt-1">{item.label}</span>
          </NavLink>
        ))}
      </div>
    </nav>
  )
}
