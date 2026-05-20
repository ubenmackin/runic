import {
  Server, Users as UsersIcon, Briefcase, Shield, FileText, Bell,
  Settings, Key, User, LayoutDashboard, Network,
} from 'lucide-react'

// Route map for parent menu activation detection
export const PARENT_ROUTE_MAP = {
  'access-control': ['/peers', '/groups', '/services', '/policies'],
  'logs': ['/logs', '/alerts'],
  'settings': ['/setup-keys', '/users', '/settings'],
}

export const isParentActive = (parentKey, pathname) => {
  const childRoutes = PARENT_ROUTE_MAP[parentKey] || []
  return childRoutes.some(route => pathname === route || pathname.startsWith(route + '/'))
}

// Shared nav items definition - single source of truth
export const NAV_ITEMS = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/topology', icon: Network, label: 'Topology' },
  {
    key: 'access-control',
    icon: Shield,
    label: 'Access Control',
    submenu: [
      { to: '/peers', icon: Server, label: 'Peers' },
      { to: '/groups', icon: UsersIcon, label: 'Groups' },
      { to: '/services', icon: Briefcase, label: 'Services' },
      { to: '/policies', icon: Shield, label: 'Policies' },
    ],
  },
  {
    key: 'logs',
    icon: FileText,
    label: 'Logs',
    submenu: [
      { to: '/logs', icon: FileText, label: 'Logs' },
      { to: '/alerts', icon: Bell, label: 'Alerts' },
    ],
  },
  {
    key: 'settings',
    icon: Settings,
    label: 'Settings',
    submenu: [
      { to: '/settings', icon: Settings, label: 'Settings' },
      { to: '/setup-keys', icon: Key, label: 'Setup Keys' },
      { to: '/users', icon: User, label: 'Users' },
    ],
  },
]

export default NAV_ITEMS
