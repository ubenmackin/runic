import React, { useState, useEffect } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, Server, Users as UsersIcon, Briefcase, Shield, FileText,
  Menu, X, LogOut, Moon, Sun, Key, Settings, User, ChevronDown, ChevronRight, Flame, Network,
  ShieldAlert, Bell
} from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { useAuthStore } from '../store'
import { useAuth } from '../hooks/useAuth'
import { getVersion } from '../api/client'
import { usePendingChanges } from '../contexts/PendingChangesContext'

const NavItem = React.memo(({ to, icon: Icon, label, onClick, isChild = false }) => (
  <NavLink
    to={to}
    end={to === '/'}
    className={({ isActive }) =>
      `flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
        isActive
? 'bg-runic-100 text-runic-700 dark:bg-purple-active/20 dark:text-light-neutral'
: 'text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest'
      } ${isChild ? 'ml-8' : ''}`
    }
    onClick={onClick}
  >
    <Icon className="w-5 h-5" />
    <span>{label}</span>
  </NavLink>
))

NavItem.displayName = 'NavItem'

const navItems = [
  { to: '/',              icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/topology',      icon: Network,          label: 'Topology' },
  { to: '/logs',          icon: FileText,         label: 'Logs' },
  { to: '/setup-keys',    icon: Key,              label: 'Setup Keys' },
  {
    label: 'Access Control',
    icon: Shield,
    children: [
      { to: '/peers',     icon: Server,           label: 'Peers' },
      { to: '/groups',    icon: UsersIcon,        label: 'Groups' },
      { to: '/services',  icon: Briefcase,        label: 'Services' },
      { to: '/policies',  icon: Shield,           label: 'Policies' },
    ]
  },
  { isDivider: true },
  { to: '/alerts',        icon: Bell,            label: 'Alerts' },
  { to: '/users',         icon: User,             label: 'Users' },
  { to: '/settings',      icon: Settings,         label: 'Settings' },
]

// Admin-only nav routes — hidden from non-admin users
const ADMIN_ONLY_ROUTES = new Set(['/users', '/setup-keys', '/alerts'])

export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [darkMode, setDarkMode] = useState(() =>
    localStorage.getItem('theme') === 'dark' ||
    (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)
  )
  const [expandedItems, setExpandedItems] = useState({})
  const logout = useAuthStore(s => s.logout)
  const username = useAuthStore(s => s.username)
  const { isAdmin, role } = useAuth()
  const navigate = useNavigate()

  // Fetch version info
  const { data: versionInfo } = useQuery({
    queryKey: ['version'],
    queryFn: getVersion,
    staleTime: Infinity, // Version doesn't change during session
  })

  // Get pending changes from context (shared with Dashboard)
  const { totalPendingCount } = usePendingChanges()

  // Apply dark class on mount and when darkMode changes
  useEffect(() => {
    document.documentElement.classList.toggle('dark', darkMode)
  }, [darkMode])

const toggleDark = () => {
	const next = !darkMode
	setDarkMode(next)
	localStorage.setItem('theme', next ? 'dark' : 'light')
}

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const toggleExpanded = (label) => {
    setExpandedItems(prev => ({
      ...prev,
      [label]: !prev[label]
    }))
  }

  // Filter nav items based on role
  const visibleNavItems = navItems.filter(item => {
    // Always show dividers
    if (item.isDivider) return true
    // Check if this is a parent with children
    if (item.children) return true
    // Hide admin-only routes from non-admins
    if (item.to && ADMIN_ONLY_ROUTES.has(item.to) && !isAdmin) return false
    return true
  })

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-charcoal-darkest flex">
      {/* Mobile sidebar backdrop */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 z-40 bg-black/50 md:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={`
        fixed md:static inset-y-0 left-0 z-50 w-60 bg-white dark:bg-charcoal-dark shadow-lg
        transform transition-transform duration-200 ease-in-out
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}
      `}>
        <div className="flex items-center justify-between h-16 px-4 border-b border-gray-200 dark:border-gray-border">
          <div className="flex items-center gap-2">
<Flame className="w-6 h-6 text-runic-600 dark:text-purple-active" />
<span className="text-xl font-bold text-runic-600 dark:text-purple-active">RUNIC</span>
<span className="hidden sm:inline text-gray-400 dark:text-amber-muted">|</span>
<span className="hidden sm:inline text-sm font-normal text-gray-500 dark:text-amber-muted whitespace-nowrap">IPTables Management</span>
            </div>
          <button className="md:hidden p-2" onClick={() => setSidebarOpen(false)}>
            <X className="w-5 h-5" />
          </button>
        </div>
        <nav className="mt-4 px-2 space-y-1">
        {visibleNavItems.map((item, index) => {
          // Render divider
          if (item.isDivider) {
            return (
              <hr
                key={`divider-${index}`}
                className="my-2 border-t border-gray-200 dark:border-gray-border"
              />
            )
          }

          if (item.children) {
            // Expandable menu item
            const isExpanded = expandedItems[item.label] || false
            // Use ShieldAlert for Access Control when there are pending changes
            const IconComponent = item.label === 'Access Control' && totalPendingCount > 0
              ? ShieldAlert
              : item.icon
            return (
              <div key={item.label}>
                <button
                  onClick={() => toggleExpanded(item.label)}
                  className={`w-full flex items-center justify-between gap-3 px-4 py-3 rounded-lg transition-colors ${
                    'text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <IconComponent className={`w-5 h-5 ${item.label === 'Access Control' && totalPendingCount > 0 ? 'text-blue-500' : ''}`} />
                    <span>{item.label}</span>
                  </div>
                  {isExpanded ? (
                    <ChevronDown className="w-4 h-4" />
                  ) : (
                    <ChevronRight className="w-4 h-4" />
                  )}
                </button>
                {isExpanded && (
                  <div className="ml-4 mt-1 space-y-1">
                    {item.children.map((child) => (
                      <NavItem
                        key={child.to}
                        to={child.to}
                        icon={child.icon}
                        label={child.label}
                        onClick={() => setSidebarOpen(false)}
                        isChild
                      />
                    ))}
                  </div>
                )}
              </div>
            )
          }

            // Regular menu item
            return (
              <NavItem
                key={item.to}
                to={item.to}
                icon={item.icon}
                label={item.label}
                onClick={() => setSidebarOpen(false)}
                isChild={false}
              />
            )
          })}
        </nav>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="h-16 bg-white dark:bg-charcoal-dark shadow-sm border-b border-gray-200 dark:border-gray-border flex items-center justify-between px-4">
          <button 
            className="md:hidden p-2"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu className="w-6 h-6" />
          </button>
          <div className="hidden md:block" />
          <div className="flex items-center gap-4">
            <button
              onClick={toggleDark}
              className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-charcoal-darkest"
            >
              {darkMode ? <Sun className="w-5 h-5 text-gray-700 dark:text-light-neutral" /> : <Moon className="w-5 h-5 text-gray-700 dark:text-light-neutral" />}
            </button>
            {username && (
              <div className="flex items-center gap-2 px-3 py-2 text-sm text-gray-700 dark:text-light-neutral">
                <User className="h-4 w-4" />
                <span>{username}</span>
                {role && (
                  <span className={`px-1.5 py-0.5 text-xs font-medium rounded-full ${
                    role === 'admin'
                      ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                      : role === 'editor'
                      ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
                      : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'
                  }`}>
                    {role}
                  </span>
                )}
              </div>
            )}
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-lg"
            >
              <LogOut className="w-4 h-4" />
              Logout
            </button>
          </div>
        </header>

          {/* Page content */}
          <main className="flex-1 p-4 md:p-6 overflow-auto">
            <Outlet />
          </main>

          {/* Footer */}
          <footer className="h-10 bg-white dark:bg-charcoal-dark border-t border-gray-200 dark:border-gray-border flex items-center justify-center">
            <p className="text-gray-400 dark:text-gray-500 text-sm">
              Runic {versionInfo?.version || '...'}
            </p>
          </footer>
        </div>
      </div>
  )
}
