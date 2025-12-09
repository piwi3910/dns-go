import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import type { ReactNode } from 'react'
import { authApi, ApiError } from '@/lib/api'

interface AuthContextType {
  isAuthenticated: boolean
  username: string | null
  isLoading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  checkAuth: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

export function createAuthProvider() {
  return function AuthProvider({ children }: { children: ReactNode }) {
    const [isAuthenticated, setIsAuthenticated] = useState(false)
    const [username, setUsername] = useState<string | null>(null)
    const [isLoading, setIsLoading] = useState(true)

    const checkAuth = useCallback(async () => {
      try {
        const data = await authApi.me()
        setIsAuthenticated(data.authenticated)
        setUsername(data.authenticated ? data.username : null)
      } catch {
        setIsAuthenticated(false)
        setUsername(null)
      } finally {
        setIsLoading(false)
      }
    }, [])

    const login = useCallback(async (username: string, password: string) => {
      try {
        await authApi.login(username, password)
        setIsAuthenticated(true)
        setUsername(username)
      } catch (error) {
        if (error instanceof ApiError) {
          throw new Error(error.message)
        }
        throw error
      }
    }, [])

    const logout = useCallback(async () => {
      try {
        await authApi.logout()
      } finally {
        setIsAuthenticated(false)
        setUsername(null)
      }
    }, [])

    useEffect(() => {
      checkAuth()
    }, [checkAuth])

    return {
      context: AuthContext,
      value: { isAuthenticated, username, isLoading, login, logout, checkAuth },
      children,
    }
  }
}

export { AuthContext }
