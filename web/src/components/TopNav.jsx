import React, { useState, useEffect, useRef, useCallback } from 'react'
import { NavLink, useNavigate, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  User,
  LogOut, Moon, Sun, ChevronDown, Flame,
} from 'lucide-react'
import { useAuthStore } from '../store'
import { useAuth } from '../hooks/useAuth'
import { useIsMobile } from '../hooks/useIsMobile'
import { getVersion } from '../api/client'
import NAV_ITEMS, { isParentActive } from './navigationConfig'

const DropdownItem = React.memo(({ to, icon: Icon, label, onClick }) => (
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
))
DropdownItem.displayName = 'DropdownItem'

const DropdownMenu = React.memo(({ label, children, isOpen, onToggle, isActive }) => {
  const dropdownRef = useRef(null)
  const closeTimeoutRef = useRef(null)
  const isMobile = useIsMobile()

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
    // Only apply hover behavior on desktop (md breakpoint and above)
    if (!isMobile) {
      if (closeTimeoutRef.current) {
        clearTimeout(closeTimeoutRef.current)
        closeTimeoutRef.current = null
      }
      onToggle(true)
    }
  }, [onToggle, isMobile])

  const handleMouseLeave = useCallback(() => {
    // Only apply hover behavior on desktop (md breakpoint and above)
    if (!isMobile) {
      closeTimeoutRef.current = setTimeout(() => {
        onToggle(false)
      }, 150)
    }
  }, [onToggle, isMobile])

  return (
    <div
      ref={dropdownRef}
      className="relative"
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      <button
        data-active={isActive ? 'true' : 'false'}
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
})
DropdownMenu.displayName = 'DropdownMenu'

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
  const isMobile = useIsMobile()
  const [darkMode, setDarkMode] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('runic_theme') === 'dark' ||
        (!localStorage.getItem('runic_theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)
    }
    return false
  })
  const [openDropdowns, setOpenDropdowns] = useState({})
  const [userDropdownOpen, setUserDropdownOpen] = useState(false)
  const userDropdownRef = useRef(null)
  const userDropdownCloseTimeoutRef = useRef(null)

  const logout = useAuthStore(s => s.logout)
  const username = useAuthStore(s => s.username)
  const { isAdmin } = useAuth()
  const navigate = useNavigate()

  const { data: versionInfo } = useQuery({
    queryKey: ['version'],
    queryFn: getVersion,
    staleTime: Infinity, // Version doesn't change during session
  })

  useEffect(() => {
    document.documentElement.classList.toggle('dark', darkMode)
  }, [darkMode])

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
    localStorage.setItem('runic_theme', next ? 'dark' : 'light')
  }

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const handleDropdownToggle = useCallback((key) => (open) => {
    setOpenDropdowns(prev => ({ ...prev, [key]: open }))
  }, [])

  const handleUserDropdownMouseEnter = useCallback(() => {
    // Only apply hover behavior on desktop (md breakpoint and above)
    if (!isMobile) {
      if (userDropdownCloseTimeoutRef.current) {
        clearTimeout(userDropdownCloseTimeoutRef.current)
        userDropdownCloseTimeoutRef.current = null
      }
      setUserDropdownOpen(true)
    }
  }, [isMobile])

  const handleUserDropdownMouseLeave = useCallback(() => {
    // Only apply hover behavior on desktop (md breakpoint and above)
    if (!isMobile) {
      userDropdownCloseTimeoutRef.current = setTimeout(() => {
        setUserDropdownOpen(false)
      }, 150)
    }
  }, [isMobile])

  const handleUserDropdownClick = useCallback(() => {
    // Toggle dropdown on mobile
    setUserDropdownOpen(prev => !prev)
  }, [])

  return (
    <header className="h-[52px] bg-white dark:bg-charcoal-dark border-b border-gray-200 dark:border-gray-border flex items-center justify-between px-4 sticky top-0 z-40">
    <div className="flex items-center gap-2">
      <Flame className="w-6 h-6 text-runic-600 dark:text-purple-active" />
      <span className="text-xl font-bold text-runic-600 dark:text-purple-active">RUNIC</span>
      <span className="hidden sm:inline text-gray-400 dark:text-amber-muted">|</span>
      <span className="hidden sm:inline text-sm font-normal text-gray-500 dark:text-amber-muted whitespace-nowrap">IPTables Management</span>
    </div>

      <nav className="hidden md:flex items-center gap-1" aria-label="Main navigation">
        {NAV_ITEMS.map(item => {
          // Simple nav items (no submenu)
          if (!item.submenu) {
            return <NavItem key={item.to} to={item.to} label={item.label} />
          }

          // Access Control and Logs dropdowns - straightforward from NAV_ITEMS
          if (item.key !== 'settings') {
            return (
              <DropdownMenu
                key={item.key}
                label={item.label}
                isOpen={openDropdowns[item.key]}
                onToggle={handleDropdownToggle(item.key)}
                isActive={isParentActive(item.key, location.pathname)}
              >
                {item.submenu.map(subItem => (
                  <DropdownItem
                    key={subItem.to}
                    to={subItem.to}
                    icon={subItem.icon}
                    label={subItem.label}
                    onClick={() => handleDropdownToggle(item.key)(false)}
                  />
                ))}
              </DropdownMenu>
            )
          }

          // Settings dropdown - special handling for dark mode toggle and admin-only items
          return (
            <DropdownMenu
              key={item.key}
              label={item.label}
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
                aria-label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
              >
                {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                <span>{darkMode ? 'Light Mode' : 'Dark Mode'}</span>
              </button>
              {/* Setup Keys - admin only */}
              {isAdmin && (
                <DropdownItem
                  to="/setup-keys"
                  icon={item.submenu.find(s => s.to === '/setup-keys').icon}
                  label="Setup Keys"
                  onClick={() => handleDropdownToggle('settings')(false)}
                />
              )}
              {/* Users - admin only */}
              {isAdmin && (
                <DropdownItem
                  to="/users"
                  icon={item.submenu.find(s => s.to === '/users').icon}
                  label="Users"
                  onClick={() => handleDropdownToggle('settings')(false)}
                />
              )}
              <DropdownItem
                to="/settings"
                icon={item.submenu.find(s => s.to === '/settings').icon}
                label="Settings"
                onClick={() => handleDropdownToggle('settings')(false)}
              />
            </DropdownMenu>
          )
        })}
      </nav>

      <div className="flex items-center gap-2">
        <div
          ref={userDropdownRef}
          className="relative"
          onMouseEnter={handleUserDropdownMouseEnter}
          onMouseLeave={handleUserDropdownMouseLeave}
        >
          <button
            onClick={handleUserDropdownClick}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-none hover:bg-gray-100 dark:hover:bg-charcoal-darkest transition-colors"
            aria-label={username ? `User menu for ${username}` : 'User menu'}
          >
            <User className="w-4 h-4 text-gray-700 dark:text-light-neutral" />
            <span className="hidden md:inline text-gray-700 dark:text-light-neutral">{username}</span>
            <ChevronDown className={`w-3.5 h-3.5 text-gray-700 dark:text-light-neutral transition-transform ${userDropdownOpen ? 'rotate-180' : ''}`} />
          </button>
          {userDropdownOpen && (
            <div
              className="absolute top-full right-0 w-48 bg-white dark:bg-charcoal-dark rounded-none border border-gray-200 dark:border-gray-border py-1 z-50"
              style={{ marginTop: '-4px', paddingTop: '4px' }}
            >
              {/* Mobile-only: Show username at top */}
              <div className="md:hidden px-3 py-2 border-b border-gray-200 dark:border-gray-border">
                <span className="font-bold text-gray-700 dark:text-light-neutral">{username}</span>
              </div>
              {/* Mobile-only: Show server version */}
              <div className="md:hidden px-3 py-2 text-sm text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-border">
                Server Version: {versionInfo?.version || '...'}
              </div>
              <button
                onClick={handleLogout}
                className="flex items-center gap-2 px-3 py-2 text-sm w-full text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none transition-colors"
                aria-label="Logout"
              >
                <LogOut className="w-4 h-4" />
                <span>Logout</span>
              </button>
              {/* Desktop-only: Show version at bottom */}
              <div className="hidden md:block px-4 py-2 text-xs text-gray-500 border-t border-gray-border">
                Runic {versionInfo?.version || '...'}
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
