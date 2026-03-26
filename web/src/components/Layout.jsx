import React, { useState, useEffect } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { 
  LayoutDashboard, Server, Users as UsersIcon, Briefcase, Shield, FileText, 
  Menu, X, LogOut, Moon, Sun, Key, Settings, User, ChevronDown, ChevronRight
} from 'lucide-react'
import { useAuthStore } from '../store'

const NavItem = React.memo(({ to, icon: Icon, label, onClick, isChild = false }) => (
  <NavLink
    to={to}
    end={to === '/'}
    className={({ isActive }) =>
      `flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
        isActive
          ? 'bg-runic-100 text-runic-700 dark:bg-runic-900 dark:text-runic-100'
          : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
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
  { to: '/users',         icon: User,             label: 'Users' },
  { to: '/settings',      icon: Settings,         label: 'Settings' },
]

export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [darkMode, setDarkMode] = useState(() =>
    localStorage.getItem('theme') === 'dark' ||
    (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)
  )
const [expandedItems, setExpandedItems] = useState({})
const logout = useAuthStore(s => s.logout)
const navigate = useNavigate()

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

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex">
      {/* Mobile sidebar backdrop */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 z-40 bg-black/50 md:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={`
        fixed md:static inset-y-0 left-0 z-50 w-60 bg-white dark:bg-gray-800 shadow-lg
        transform transition-transform duration-200 ease-in-out
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}
      `}>
        <div className="flex items-center justify-between h-16 px-4 border-b border-gray-200 dark:border-gray-700">
          <span className="text-xl font-bold text-runic-600 dark:text-runic-400">Runic</span>
          <button className="md:hidden p-2" onClick={() => setSidebarOpen(false)}>
            <X className="w-5 h-5" />
          </button>
        </div>
        <nav className="mt-4 px-2 space-y-1">
          {navItems.map((item) => {
            if (item.children) {
              // Expandable menu item
              const isExpanded = expandedItems[item.label] || false
              return (
                <div key={item.label}>
                  <button
                    onClick={() => toggleExpanded(item.label)}
                    className={`w-full flex items-center justify-between gap-3 px-4 py-3 rounded-lg transition-colors ${
                      'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <item.icon className="w-5 h-5" />
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
        <header className="h-16 bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700 flex items-center justify-between px-4">
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
              className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
            >
              {darkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-3 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
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
      </div>
    </div>
  )
}
