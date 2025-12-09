import { Outlet } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { Header } from './Header'

interface MainLayoutProps {
  connected: boolean
  onLogout: () => void
}

export function MainLayout({ connected, onLogout }: MainLayoutProps) {
  return (
    <div className="flex h-screen bg-background">
      <Sidebar connected={connected} onLogout={onLogout} />
      <div className="flex flex-1 flex-col">
        <Header onLogout={onLogout} />
        <main className="flex-1 overflow-auto bg-background">
          <div className="mx-auto max-w-7xl p-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}
