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
    <aside className="flex h-screen w-64 flex-col border-r bg-card/50 backdrop-blur-xl">
      {/* Logo Section */}
      <div className="flex h-16 items-center gap-3 border-b px-6">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-primary/60 shadow-lg shadow-primary/25">
          <Sparkles className="h-5 w-5 text-primary-foreground" />
        </div>
        <div>
          <span className="text-lg font-bold tracking-tight">DNS Server</span>
          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Control Panel</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 p-4">
        <p className="mb-2 px-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Menu
        </p>
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              cn(
                'group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-200',
                isActive
                  ? 'bg-primary text-primary-foreground shadow-lg shadow-primary/25'
                  : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground hover:translate-x-1'
              )
            }
          >
            <item.icon className="h-4 w-4 transition-transform group-hover:scale-110" />
            {item.label}
          </NavLink>
        ))}
      </nav>

      {/* Footer Section */}
      <div className="border-t p-4 space-y-3">
        {/* Theme Toggle */}
        <ThemeToggle />

        {/* Connection Status */}
        <div className="flex items-center gap-2 rounded-lg bg-muted/50 px-3 py-2 text-sm">
          {connected ? (
            <>
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
              </span>
              <span className="text-emerald-500 font-medium">Connected</span>
            </>
          ) : (
            <>
              <WifiOff className="h-4 w-4 text-red-500" />
              <span className="text-red-500 font-medium">Disconnected</span>
            </>
          )}
        </div>

        {/* Logout Button */}
        <button
          onClick={onLogout}
          className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-muted-foreground transition-all duration-200 hover:bg-destructive/10 hover:text-destructive hover:translate-x-1"
        >
          <LogOut className="h-4 w-4" />
          Logout
        </button>
      </div>
    </aside>
  )
}
