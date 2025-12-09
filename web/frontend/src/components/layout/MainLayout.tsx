import { Outlet } from 'react-router-dom'
import { Sidebar } from './Sidebar'

interface MainLayoutProps {
  connected: boolean
  onLogout: () => void
}

export function MainLayout({ connected, onLogout }: MainLayoutProps) {
  return (
    <div className="flex h-screen bg-background">
      <Sidebar connected={connected} onLogout={onLogout} />
      <main className="flex-1 overflow-auto">
        <div className="container mx-auto p-6">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
