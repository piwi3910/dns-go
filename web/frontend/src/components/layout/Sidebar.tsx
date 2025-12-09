import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  Globe,
  Server,
  Database,
  Settings,
  LogOut,
  WifiOff,
  Sparkles,
  Network,
  Users,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { ThemeToggle } from '../ThemeToggle'

interface SidebarProps {
  connected: boolean
  onLogout: () => void
}

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/clusters', icon: Network, label: 'Clusters' },
  { to: '/workers', icon: Users, label: 'Workers' },
  { to: '/zones', icon: Globe, label: 'Zones' },
  { to: '/upstreams', icon: Server, label: 'Upstreams' },
  { to: '/cache', icon: Database, label: 'Cache' },
  { to: '/config', icon: Settings, label: 'Configuration' },
]

export function Sidebar({ connected, onLogout }: SidebarProps) {
  return (
    <aside className="sidebar-nav flex h-screen w-64 flex-col border-r">
      {/* Logo Section */}
      <div className="sidebar-logo flex h-14 items-center gap-3 border-b px-5">
        <div className="sidebar-logo-icon flex h-8 w-8 items-center justify-center rounded-md">
          <Sparkles className="h-4 w-4" />
        </div>
        <div>
          <span className="sidebar-title text-base font-semibold">DNS Server</span>
          <p className="sidebar-subtitle text-[10px] uppercase tracking-wide">Control Panel</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-0.5 p-3">
        <p className="sidebar-section-title mb-3 px-3 text-[11px] font-medium uppercase tracking-wider">
          Navigation
        </p>
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              cn(
                'sidebar-nav-link flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium',
                isActive && 'sidebar-nav-link-active'
              )
            }
          >
            <item.icon className="h-4 w-4" />
            {item.label}
          </NavLink>
        ))}
      </nav>

      {/* Footer Section */}
      <div className="sidebar-footer border-t p-3 space-y-2">
        {/* Theme Toggle */}
        <ThemeToggle />

        {/* Connection Status */}
        <div className="sidebar-status flex items-center gap-2 rounded-md px-3 py-2 text-sm">
          {connected ? (
            <>
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              <span className="text-emerald-500 text-xs font-medium">Connected</span>
            </>
          ) : (
            <>
              <WifiOff className="h-3.5 w-3.5 text-red-500" />
              <span className="text-red-500 text-xs font-medium">Disconnected</span>
            </>
          )}
        </div>

        {/* Logout Button */}
        <button
          onClick={onLogout}
          className="sidebar-logout flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium"
        >
          <LogOut className="h-4 w-4" />
          Logout
        </button>
      </div>
    </aside>
  )
}
