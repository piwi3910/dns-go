import { useState, useEffect, useCallback } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { ThemeProvider } from '@/components/ThemeProvider'
import { MainLayout } from '@/components/layout/MainLayout'
import { Login } from '@/pages/Login'
import { Dashboard } from '@/pages/Dashboard'
import { Clusters } from '@/pages/Clusters'
import { Workers } from '@/pages/Workers'
import { Zones } from '@/pages/Zones'
import { Upstreams } from '@/pages/Upstreams'
import { Cache } from '@/pages/Cache'
import { Config } from '@/pages/Config'
import { useSSE } from '@/hooks/useSSE'
import { authApi, ApiError } from '@/lib/api'
import type { Stats } from '@/lib/api'

function AppContent() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)

  const { stats, connected } = useSSE({ enabled: isAuthenticated })

  const checkAuth = useCallback(async () => {
    try {
      const data = await authApi.me()
      setIsAuthenticated(data.authenticated)
    } catch {
      setIsAuthenticated(false)
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    checkAuth()
  }, [checkAuth])

  const handleLogin = async (username: string, password: string) => {
    try {
      await authApi.login(username, password)
      setIsAuthenticated(true)
    } catch (error) {
      if (error instanceof ApiError) {
        throw new Error(error.message)
      }
      throw error
    }
  }

  const handleLogout = async () => {
    try {
      await authApi.logout()
    } finally {
      setIsAuthenticated(false)
    }
  }

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="text-center">
          <div className="mb-4 h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent mx-auto" />
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Login onLogin={handleLogin} />
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<MainLayout connected={connected} onLogout={handleLogout} />}>
          <Route path="/" element={<Dashboard stats={stats as Stats | null} />} />
          <Route path="/clusters" element={<Clusters />} />
          <Route path="/workers" element={<Workers />} />
          <Route path="/zones" element={<Zones />} />
          <Route path="/upstreams" element={<Upstreams />} />
          <Route path="/cache" element={<Cache />} />
          <Route path="/config" element={<Config />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

function App() {
  return (
    <ThemeProvider defaultTheme="dark" storageKey="dns-gui-theme">
      <AppContent />
    </ThemeProvider>
  )
}

export default App
