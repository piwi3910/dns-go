import { User, Settings, LogOut, ChevronDown, Bell, Search } from 'lucide-react'
import { useState, useRef, useEffect } from 'react'
import { cn } from '@/lib/utils'

interface HeaderProps {
  onLogout: () => void
}

export function Header({ onLogout }: HeaderProps) {
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)

  // Close menu when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setUserMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  return (
    <header className="header-bar h-14 border-b flex items-center justify-between px-6">
      {/* Left side - Search or breadcrumb area */}
      <div className="flex items-center gap-4">
        <div className="relative">
          <Search className="header-search-icon absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" />
          <input
            type="text"
            placeholder="Search..."
            className="header-search-input h-9 w-64 rounded-md border pl-9 pr-4 text-sm focus:outline-none focus:ring-2"
          />
        </div>
      </div>

      {/* Right side - Notifications & User menu */}
      <div className="flex items-center gap-3">
        {/* Notifications */}
        <button className="header-icon-btn relative p-2 rounded-md">
          <Bell className="h-5 w-5" />
          <span className="absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-amber-500" />
        </button>

        {/* User Menu */}
        <div className="relative" ref={menuRef}>
          <button
            onClick={() => setUserMenuOpen(!userMenuOpen)}
            className={cn(
              'header-user-btn flex items-center gap-3 rounded-md px-3 py-1.5',
              userMenuOpen && 'header-user-btn-active'
            )}
          >
            <div className="header-avatar h-8 w-8 rounded-full border flex items-center justify-center">
              <User className="h-4 w-4" />
            </div>
            <div className="text-left hidden sm:block">
              <p className="header-user-name text-sm font-medium">Admin User</p>
              <p className="header-user-email text-xs">admin@example.com</p>
            </div>
            <ChevronDown className={cn(
              'header-chevron h-4 w-4 transition-transform',
              userMenuOpen && 'rotate-180'
            )} />
          </button>

          {/* Dropdown Menu */}
          {userMenuOpen && (
            <div className="header-dropdown absolute right-0 top-full mt-2 w-56 rounded-md shadow-lg py-1 z-50">
              <div className="header-dropdown-header px-3 py-2">
                <p className="header-dropdown-name text-sm font-medium">Admin User</p>
                <p className="header-dropdown-email text-xs">admin@example.com</p>
              </div>

              <div className="py-1">
                <button className="header-dropdown-item w-full flex items-center gap-3 px-3 py-2 text-sm">
                  <User className="h-4 w-4" />
                  Profile
                </button>
                <button className="header-dropdown-item w-full flex items-center gap-3 px-3 py-2 text-sm">
                  <Settings className="h-4 w-4" />
                  Settings
                </button>
              </div>

              <div className="header-dropdown-divider py-1">
                <button
                  onClick={() => {
                    setUserMenuOpen(false)
                    onLogout()
                  }}
                  className="header-dropdown-logout w-full flex items-center gap-3 px-3 py-2 text-sm"
                >
                  <LogOut className="h-4 w-4" />
                  Logout
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
