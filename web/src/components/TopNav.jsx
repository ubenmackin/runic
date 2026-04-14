import { useState, useEffect, useRef } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, Network, Shield, FileText, Settings, User,
  LogOut, Moon, Sun, ChevronDown, Flame, Server, Users as UsersIcon,
  Briefcase, Bell, Key, Menu
} from 'lucide-react'
import { useAuthStore } from '../store'
import { useAuth } from '../hooks/useAuth'

// Dropdown menu item component
const DropdownItem = ({ to, icon: Icon, label, onClick }) => (
  <NavLink
    to={to}
    onClick={onClick}
    className={({ isActive }) =>
      `flex items-center gap-2 px-3 py-2 text-sm rounded-none transition-colors ${
        isActive
          ? 'bg-runic-100 text-runic-700 dark:bg-purple-active/20 dark:text-light-neutral'
          : 'text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest'
      }`
    }
  >
    <Icon className="w-4 h-4" />
    <span>{label}</span>
  </NavLink>
)

// Dropdown menu component
const DropdownMenu = ({ label, icon: Icon, children, isOpen, onToggle }) => {
  const dropdownRef = useRef(null)

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

  return (
    <div
      ref={dropdownRef}
      className="relative"
      onMouseEnter={() => onToggle(true)}
      onMouseLeave={() => onToggle(false)}
    >
      <button
        className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-none transition-colors ${
          isOpen
            ? 'bg-gray-100 dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral'
            : 'text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest'
        }`}
      >
        <Icon className="w-4 h-4" />
        <span className="hidden lg:inline">{label}</span>
        <ChevronDown className={`w-3.5 h-3.5 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>
      {isOpen && (
        <div className="absolute top-full left-0 mt-1 w-48 bg-white dark:bg-charcoal-dark rounded-none border border-gray-200 dark:border-gray-border py-1 z-50">
          {children}
        </div>
      )}
    </div>
  )
}

// Navigation link component
const NavItem = ({ to, icon: Icon, label }) => (
  <NavLink
    to={to}
    end={to === '/'}
    className={({ isActive }) =>
      `flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-none transition-colors ${
        isActive
          ? 'bg-runic-100 text-runic-700 dark:bg-purple-active/20 dark:text-light-neutral'
          : 'text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest'
      }`
    }
  >
    <Icon className="w-4 h-4" />
    <span className="hidden lg:inline">{label}</span>
  </NavLink>
)

export default function TopNav() {
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

  const logout = useAuthStore(s => s.logout)
  const username = useAuthStore(s => s.username)
  const { isAdmin } = useAuth()
  const navigate = useNavigate()

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

  return (
    <header className="h-[52px] bg-white dark:bg-charcoal-dark border-b border-gray-200 dark:border-gray-border flex items-center justify-between px-4 sticky top-0 z-40">
      {/* Brand / Logo */}
      <div className="flex items-center gap-2">
        <Flame className="w-6 h-6 text-runic-600 dark:text-purple-active" />
        <span className="text-xl font-bold text-runic-600 dark:text-purple-active">RUNIC</span>
      </div>

      {/* Desktop Navigation */}
      <nav className="hidden md:flex items-center gap-1">
        {/* Dashboard */}
        <NavItem to="/" icon={LayoutDashboard} label="Dashboard" />

        {/* Topology */}
        <NavItem to="/topology" icon={Network} label="Topology" />

        {/* Access Control Dropdown */}
        <DropdownMenu
          label="Access Control"
          icon={Shield}
          isOpen={openDropdowns['access-control']}
          onToggle={handleDropdownToggle('access-control')}
        >
          <DropdownItem to="/peers" icon={Server} label="Peers" onClick={() => handleDropdownToggle('access-control')(false)} />
          <DropdownItem to="/groups" icon={UsersIcon} label="Groups" onClick={() => handleDropdownToggle('access-control')(false)} />
          <DropdownItem to="/services" icon={Briefcase} label="Services" onClick={() => handleDropdownToggle('access-control')(false)} />
          <DropdownItem to="/policies" icon={Shield} label="Policies" onClick={() => handleDropdownToggle('access-control')(false)} />
        </DropdownMenu>

        {/* Logs Dropdown */}
        <DropdownMenu
          label="Logs"
          icon={FileText}
          isOpen={openDropdowns['logs']}
          onToggle={handleDropdownToggle('logs')}
        >
          <DropdownItem to="/logs" icon={FileText} label="Logs" onClick={() => handleDropdownToggle('logs')(false)} />
          <DropdownItem to="/alerts" icon={Bell} label="Alerts" onClick={() => handleDropdownToggle('logs')(false)} />
        </DropdownMenu>

        {/* Settings Dropdown */}
        <DropdownMenu
          label="Settings"
          icon={Settings}
          isOpen={openDropdowns['settings']}
          onToggle={handleDropdownToggle('settings')}
        >
          <button
            onClick={() => {
              toggleDark()
              handleDropdownToggle('settings')(false)
            }}
            className="flex items-center gap-2 px-3 py-2 text-sm w-full text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none transition-colors"
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
          onMouseEnter={() => setUserDropdownOpen(true)}
          onMouseLeave={() => setUserDropdownOpen(false)}
        >
          <button
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-none hover:bg-gray-100 dark:hover:bg-charcoal-darkest transition-colors"
          >
            <User className="w-4 h-4 text-gray-700 dark:text-light-neutral" />
            <span className="hidden sm:inline text-gray-700 dark:text-light-neutral">{username}</span>
            <ChevronDown className={`w-3.5 h-3.5 text-gray-700 dark:text-light-neutral transition-transform ${userDropdownOpen ? 'rotate-180' : ''}`} />
          </button>
          {userDropdownOpen && (
            <div className="absolute top-full right-0 mt-1 w-40 bg-white dark:bg-charcoal-dark rounded-none border border-gray-200 dark:border-gray-border py-1 z-50">
              <button
                onClick={handleLogout}
className="flex items-center gap-2 px-3 py-2 text-sm w-full text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none transition-colors"
              >
                <LogOut className="w-4 h-4" />
                <span>Logout</span>
              </button>
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
              <NavItem to="/" icon={LayoutDashboard} label="Dashboard" />
              <NavItem to="/topology" icon={Network} label="Topology" />
              <div className="py-2">
                <span className="px-3 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Access Control</span>
              </div>
<NavLink to="/peers" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none">Peers</NavLink>
<NavLink to="/groups" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none">Groups</NavLink>
<NavLink to="/services" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none">Services</NavLink>
<NavLink to="/policies" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none">Policies</NavLink>
              <div className="py-2">
                <span className="px-3 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Logs</span>
              </div>
<NavLink to="/logs" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none">Logs</NavLink>
<NavLink to="/alerts" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none">Alerts</NavLink>
              <div className="py-2">
                <span className="px-3 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Settings</span>
              </div>
              <button
                onClick={toggleDark}
                className="flex items-center gap-2 w-full px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none"
              >
                {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                <span>{darkMode ? 'Light Mode' : 'Dark Mode'}</span>
              </button>
              {isAdmin && (
<NavLink to="/setup-keys" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none">Setup Keys</NavLink>
)}
{isAdmin && (
<NavLink to="/users" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none">Users</NavLink>
)}
<NavLink to="/settings" className="block px-3 py-2 text-sm text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none">Settings</NavLink>
            </nav>
          </div>
        </div>
      )}
    </header>
  )
}
