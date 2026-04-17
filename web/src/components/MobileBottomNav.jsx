import { useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { LayoutDashboard, Network, Shield, FileText, Settings, ChevronUp } from 'lucide-react'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/topology', icon: Network, label: 'Topology' },
  {
    key: 'access-control',
    icon: Shield,
    label: 'Access Control',
    submenu: [
      { to: '/peers', label: 'Peers' },
      { to: '/groups', label: 'Groups' },
      { to: '/services', label: 'Services' },
      { to: '/policies', label: 'Policies' },
    ],
  },
  {
    key: 'logs',
    icon: FileText,
    label: 'Logs',
    submenu: [
      { to: '/logs', label: 'Logs' },
      { to: '/alerts', label: 'Alerts' },
    ],
  },
  {
    key: 'settings',
    icon: Settings,
    label: 'Settings',
    submenu: [
      { to: '/settings', label: 'Settings' },
      { to: '/setup-keys', label: 'Setup Keys' },
      { to: '/users', label: 'Users' },
    ],
  },
]

export default function MobileBottomNav() {
  const [openSubmenu, setOpenSubmenu] = useState(null)
  const location = useLocation()

  const isSubmenuActive = (item) => {
    if (!item.submenu) return false
    return item.submenu.some((sub) => location.pathname === sub.to)
  }

  const handleItemClick = (item) => {
    if (item.submenu) {
      if (openSubmenu === item.key) {
        setOpenSubmenu(null)
      } else {
        setOpenSubmenu(item.key)
      }
    }
  }

  const handleSubmenuItemClick = () => {
    setOpenSubmenu(null)
  }

  const handleBackdropClick = () => {
    setOpenSubmenu(null)
  }

  return (
    <>
      {/* Backdrop overlay for submenu */}
      {openSubmenu && (
        <div
          className="fixed inset-0 bg-black/50 z-40 md:hidden"
          onClick={handleBackdropClick}
          data-testid="submenu-backdrop"
        />
      )}

      <nav className="fixed bottom-0 left-0 right-0 h-16 bg-charcoal-dark border-t border-gray-border md:hidden">
        <div className="flex items-center justify-around h-full">
          {navItems.map((item) => {
            const hasSubmenu = !!item.submenu
            const isOpen = openSubmenu === item.key
            const isActive = hasSubmenu ? isSubmenuActive(item) : false

            return (
              <div key={item.to || item.key} className="relative">
                {/* Submenu popup */}
                {hasSubmenu && isOpen && (
                  <div
                    className="absolute bottom-full mb-2 left-1/2 -translate-x-1/2 bg-charcoal-dark border border-gray-border rounded-lg shadow-lg min-w-[120px] py-1 z-50"
                    data-testid={`submenu-${item.key}`}
                  >
                    {item.submenu.map((subItem) => (
                      <NavLink
                        key={subItem.to}
                        to={subItem.to}
                        onClick={handleSubmenuItemClick}
                        className={({ isActive: subIsActive }) =>
                          `block px-4 py-2 text-sm text-center transition-colors ${
                            subIsActive
                              ? 'text-purple-active bg-purple-active/10'
                              : 'text-gray-400 hover:text-light-neutral'
                          }`
                        }
                      >
                        {subItem.label}
                      </NavLink>
                    ))}
                  </div>
                )}

                {/* Nav item */}
                {hasSubmenu ? (
                  <button
                    onClick={() => handleItemClick(item)}
                    className={`flex flex-col items-center justify-center px-3 py-2 transition-colors ${
                      isActive || isOpen
                        ? 'text-purple-active'
                        : 'text-gray-400 hover:text-light-neutral'
                    }`}
                    data-testid={`nav-item-${item.key}`}
                  >
                    <item.icon className="w-5 h-5" />
                    <span className="text-xs mt-1">{item.label}</span>
                    <ChevronUp
                      className={`w-3 h-3 transition-transform ${isOpen ? 'rotate-180' : ''}`}
                    />
                  </button>
                ) : (
                  <NavLink
                    to={item.to}
                    end={item.to === '/'}
                    className={({ isActive: navIsActive }) =>
                      `flex flex-col items-center justify-center px-3 py-2 transition-colors ${
                        navIsActive
                          ? 'text-purple-active'
                          : 'text-gray-400 hover:text-light-neutral'
                      }`
                    }
                  >
                    <item.icon className="w-5 h-5" />
                    <span className="text-xs mt-1">{item.label}</span>
                  </NavLink>
                )}
              </div>
            )
          })}
        </div>
      </nav>
    </>
  )
}
