import { useState, useEffect, useRef, useCallback } from 'react'
import { NavLink, useNavigate, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Shield, FileText, Settings, User,
  LogOut, Moon, Sun, ChevronDown, Flame, Server, Users as UsersIcon,
  Briefcase, Bell, Key, Menu
} from 'lucide-react'
import { useAuthStore } from '../store'
import { useAuth } from '../hooks/useAuth'
import { getVersion } from '../api/client'

// Dropdown menu item component
const DropdownItem = ({ to, icon: Icon, label, onClick }) => (
  <NavLink
    to={to}
    onClick={onClick}
className={({ isActive }) =>
  `flex items-center gap-2 px-3 py-2 text-sm rounded-none transition-colors ${
    isActive
? 'bg-purple-active/10 text-purple-active'
: 'text-slate-500 hover:text-white hover:bg-gray-100 dark:hover:bg-charcoal-darkest'
  }`
}
  >
    <Icon className="w-4 h-4" />
    <span className="uppercase">{label}</span>
  </NavLink>
)

// Route mapping for parent menu active states
const PARENT_ROUTE_MAP = {
  'access-control': ['/peers', '/groups', '/services', '/policies'],
  'logs': ['/logs', '/alerts'],
  'settings': ['/setup-keys', '/users', '/settings']
}

// Helper function to check if any child route is active
const isParentActive = (parentKey, pathname) => {
  const childRoutes = PARENT_ROUTE_MAP[parentKey] || []
  return childRoutes.some(route => pathname === route || pathname.startsWith(route + '/'))
}

// Dropdown menu component
const DropdownMenu = ({ label, children, isOpen, onToggle, isActive }) => {
  const dropdownRef = useRef(null)
  const closeTimeoutRef = useRef(null)

  // Clear timeout on unmount
  useEffect(() => {
    return () => {
      if (closeTimeoutRef.current) {
        clearTimeout(closeTimeoutRef.current)
      }
    }
  }, [])

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        onToggle(false)
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside)
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [isOpen, onToggle])

  const handleMouseEnter = useCallback(() => {
    // Clear any pending close timeout
    if (closeTimeoutRef.current) {
      clearTimeout(closeTimeoutRef.current)
      closeTimeoutRef.current = null
    }
    onToggle(true)
  }, [onToggle])

  const handleMouseLeave = useCallback(() => {
    // Delay closing to allow user to move to dropdown
    closeTimeoutRef.current = setTimeout(() => {
      onToggle(false)
    }, 150)
  }, [onToggle])

  return (
    <div
      ref={dropdownRef}
      className="relative"
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      <button
className={`flex items-center justify-center gap-1.5 px-5 h-[52px] text-sm font-medium rounded-none transition-colors border-b-2 ${
  isActive
    ? 'bg-purple-active/10 text-purple-active border-purple-active'
    : isOpen
? 'bg-gray-100 dark:bg-charcoal-darkest text-white border-transparent'
: 'text-slate-500 hover:text-white hover:bg-gray-100 dark:hover:bg-charcoal-darkest border-transparent'
}`}
      >
        <span className="hidden lg:inline uppercase">{label}</span>
        <ChevronDown className={`w-3.5 h-3.5 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>
      {isOpen && (
        <div
          className="absolute top-full left-0 w-48 bg-white dark:bg-charcoal-dark rounded-none border border-gray-200 dark:border-gray-border py-1 z-50"
          style={{ marginTop: '-4px', paddingTop: '4px' }}
        >
          {children}
        </div>
      )}
    </div>
  )
}

// Navigation link component
const NavItem = ({ to, label }) => (
  <NavLink
    to={to}
    end={to === '/'}
className={({ isActive }) =>
  `flex items-center justify-center gap-1.5 px-5 h-[52px] text-sm font-medium rounded-none transition-colors border-b-2 ${
    isActive
? 'bg-purple-active/10 text-purple-active border-purple-active'
: 'text-slate-500 hover:text-white hover:bg-gray-100 dark:hover:bg-charcoal-darkest border-transparent'
  }`
}
  >
    <span className="hidden lg:inline uppercase">{label}</span>
  </NavLink>
)

export default function TopNav() {
  const location = useLocation()
  const [darkMode, setDarkMode] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('theme') === 'dark' ||
        (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)
    }
    return false
  })
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [openDropdowns, setOpenDropdowns] = useState({})
  const [userDropdownOpen, setUserDropdownOpen] = useState(false)
  const userDropdownRef = useRef(null)
  const userDropdownCloseTimeoutRef = useRef(null)

  const logout = useAuthStore(s => s.logout)
  const username = useAuthStore(s => s.username)
  const { isAdmin } = useAuth()
  const navigate = useNavigate()

  // Fetch version info
  const { data: versionInfo } = useQuery({
    queryKey: ['version'],
    queryFn: getVersion,
    staleTime: Infinity, // Version doesn't change during session
  })

  // Apply dark class on mount and when darkMode changes
  useEffect(() => {
    document.documentElement.classList.toggle('dark', darkMode)
  }, [darkMode])

  // Close user dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (userDropdownRef.current && !userDropdownRef.current.contains(event.target)) {
        setUserDropdownOpen(false)
      }
    }

    if (userDropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside)
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [userDropdownOpen])

  // Clear timeout on unmount
  useEffect(() => {
    return () => {
      if (userDropdownCloseTimeoutRef.current) {
        clearTimeout(userDropdownCloseTimeoutRef.current)
      }
    }
  }, [])

  const toggleDark = () => {
    const next = !darkMode
    setDarkMode(next)
    localStorage.setItem('theme', next ? 'dark' : 'light')
  }

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const handleDropdownToggle = (key) => (open) => {
    setOpenDropdowns(prev => ({ ...prev, [key]: open }))
  }

  const handleUserDropdownMouseEnter = useCallback(() => {
    // Clear any pending close timeout
    if (userDropdownCloseTimeoutRef.current) {
      clearTimeout(userDropdownCloseTimeoutRef.current)
      userDropdownCloseTimeoutRef.current = null
    }
    setUserDropdownOpen(true)
  }, [])

  const handleUserDropdownMouseLeave = useCallback(() => {
    // Delay closing to allow user to move to dropdown
    userDropdownCloseTimeoutRef.current = setTimeout(() => {
      setUserDropdownOpen(false)
    }, 150)
  }, [])

  return (
    <header className="h-[52px] bg-white dark:bg-charcoal-dark border-b border-gray-200 dark:border-gray-border flex items-center justify-between px-4 sticky top-0 z-40">
    {/* Brand / Logo */}
    <div className="flex items-center gap-2">
      <Flame className="w-6 h-6 text-runic-600 dark:text-purple-active" />
      <span className="text-xl font-bold text-runic-600 dark:text-purple-active">RUNIC</span>
      <span className="hidden sm:inline text-gray-400 dark:text-amber-muted">|</span>
      <span className="hidden sm:inline text-sm font-normal text-gray-500 dark:text-amber-muted whitespace-nowrap">IPTables Management</span>
    </div>

      {/* Desktop Navigation */}
      <nav className="hidden md:flex items-center gap-1">
      {/* Dashboard */}
      <NavItem to="/" label="Dashboard" />

      {/* Topology */}
      <NavItem to="/topology" label="Topology" />

      {/* Access Control Dropdown */}
      <DropdownMenu
        label="Access Control"
        isOpen={openDropdowns['access-control']}
        onToggle={handleDropdownToggle('access-control')}
        isActive={isParentActive('access-control', location.pathname)}
      >
          <DropdownItem to="/peers" icon={Server} label="Peers" onClick={() => handleDropdownToggle('access-control')(false)} />
          <DropdownItem to="/groups" icon={UsersIcon} label="Groups" onClick={() => handleDropdownToggle('access-control')(false)} />
          <DropdownItem to="/services" icon={Briefcase} label="Services" onClick={() => handleDropdownToggle('access-control')(false)} />
          <DropdownItem to="/policies" icon={Shield} label="Policies" onClick={() => handleDropdownToggle('access-control')(false)} />
        </DropdownMenu>

      {/* Logs Dropdown */}
      <DropdownMenu
        label="Logs"
        isOpen={openDropdowns['logs']}
        onToggle={handleDropdownToggle('logs')}
        isActive={isParentActive('logs', location.pathname)}
      >
          <DropdownItem to="/logs" icon={FileText} label="Logs" onClick={() => handleDropdownToggle('logs')(false)} />
          <DropdownItem to="/alerts" icon={Bell} label="Alerts" onClick={() => handleDropdownToggle('logs')(false)} />
        </DropdownMenu>

      {/* Settings Dropdown */}
      <DropdownMenu
        label="Settings"
        isOpen={openDropdowns['settings']}
        onToggle={handleDropdownToggle('settings')}
        isActive={isParentActive('settings', location.pathname)}
      >
          <button
            onClick={() => {
              toggleDark()
              handleDropdownToggle('settings')(false)
            }}
            className="flex items-center gap-2 px-3 py-2 text-sm w-full text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none transition-colors uppercase"
          >
            {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            <span>{darkMode ? 'Light Mode' : 'Dark Mode'}</span>
          </button>
          {isAdmin && (
            <DropdownItem to="/setup-keys" icon={Key} label="Setup Keys" onClick={() => handleDropdownToggle('settings')(false)} />
          )}
          {isAdmin && (
            <DropdownItem to="/users" icon={User} label="Users" onClick={() => handleDropdownToggle('settings')(false)} />
          )}
          <DropdownItem to="/settings" icon={Settings} label="Settings" onClick={() => handleDropdownToggle('settings')(false)} />
        </DropdownMenu>
      </nav>

      {/* Right side: Mobile menu + User dropdown */}
      <div className="flex items-center gap-2">
        {/* Mobile menu button */}
        <button
          className="md:hidden p-2 rounded-none hover:bg-gray-100 dark:hover:bg-charcoal-darkest"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          aria-label="Toggle menu"
        >
          <Menu className="w-5 h-5 text-gray-700 dark:text-light-neutral" />
        </button>

      {/* Username dropdown */}
      <div
        ref={userDropdownRef}
        className="relative"
        onMouseEnter={handleUserDropdownMouseEnter}
        onMouseLeave={handleUserDropdownMouseLeave}
      >
        <button
          className="flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-none hover:bg-gray-100 dark:hover:bg-charcoal-darkest transition-colors"
        >
          <User className="w-4 h-4 text-gray-700 dark:text-light-neutral" />
          <span className="hidden sm:inline text-gray-700 dark:text-light-neutral">{username}</span>
          <ChevronDown className={`w-3.5 h-3.5 text-gray-700 dark:text-light-neutral transition-transform ${userDropdownOpen ? 'rotate-180' : ''}`} />
        </button>
        {userDropdownOpen && (
          <div
            className="absolute top-full right-0 w-40 bg-white dark:bg-charcoal-dark rounded-none border border-gray-200 dark:border-gray-border py-1 z-50"
            style={{ marginTop: '-4px', paddingTop: '4px' }}
          >
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-3 py-2 text-sm w-full text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none transition-colors"
            >
              <LogOut className="w-4 h-4" />
              <span>Logout</span>
            </button>
            <div className="px-4 py-2 text-xs text-gray-500 border-t border-gray-border">
              Runic {versionInfo?.version || '...'}
            </div>
          </div>
        )}
      </div>
      </div>

      {/* Mobile menu overlay */}
      {mobileMenuOpen && (
        <div className="md:hidden fixed inset-0 top-[52px] bg-black/50 z-30" onClick={() => setMobileMenuOpen(false)}>
          <div
            className="absolute top-0 right-0 w-64 h-full bg-white dark:bg-charcoal-dark"
            onClick={(e) => e.stopPropagation()}
          >
<nav className="p-4 space-y-1">
            <NavItem to="/" label="Dashboard" />
            <NavItem to="/topology" label="Topology" />
              <div className="py-2">
                <span className="px-3 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Access Control</span>
              </div>
<NavLink to="/peers" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none uppercase">Peers</NavLink>
<NavLink to="/groups" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none uppercase">Groups</NavLink>
<NavLink to="/services" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none uppercase">Services</NavLink>
<NavLink to="/policies" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none uppercase">Policies</NavLink>
              <div className="py-2">
                <span className="px-3 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Logs</span>
              </div>
<NavLink to="/logs" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none uppercase">Logs</NavLink>
              <NavLink to="/alerts" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none uppercase">Alerts</NavLink>
              <div className="py-2">
                <span className="px-3 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Settings</span>
              </div>
<button
                onClick={toggleDark}
                className="flex items-center gap-2 w-full px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none uppercase"
              >
                {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                <span>{darkMode ? 'Light Mode' : 'Dark Mode'}</span>
              </button>
              {isAdmin && (
                <NavLink to="/setup-keys" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none uppercase">Setup Keys</NavLink>
              )}
              {isAdmin && (
                <NavLink to="/users" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none uppercase">Users</NavLink>
              )}
              <NavLink to="/settings" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none uppercase">Settings</NavLink>
            </nav>
          </div>
        </div>
      )}
    </header>
  )
}
