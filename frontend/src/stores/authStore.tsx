import { create } from 'zustand'

export type UserRole = 'admin' | 'analyst' | 'viewer' | 'client'

export interface User {
  id: string
  email: string
  full_name: string | null
  role: UserRole
  is_active: boolean
  is_verified: boolean
  created_at: string
  updated_at: string
}

interface AuthState {
  user: User | null
  isAuthenticated: boolean
  login: (token: string, user: User) => void
  logout: () => void
  updateUser: (user: Partial<User>) => void
  isAdmin: () => boolean
  isAnalyst: () => boolean
  canEdit: () => boolean
  canCreateScans: () => boolean
}

export const useAuthStore = create<AuthState>()((set, get) => ({
  user: null,
  isAuthenticated: false,
  login: (_token, user) => {
    // Token is now stored in HttpOnly cookie, not in localStorage
    // We accept the token param for API compatibility but don't store it client-side
    set({ user, isAuthenticated: true })
  },
  logout: () => {
    // Clear user state - cookies are cleared by backend
    set({ user: null, isAuthenticated: false })
  },
  updateUser: (updates) => {
    const currentUser = get().user
    if (currentUser) {
      const updatedUser = { ...currentUser, ...updates }
      set({ user: updatedUser })
    }
  },
  isAdmin: () => {
    return get().user?.role === 'admin'
  },
  isAnalyst: () => {
    const role = get().user?.role
    return role === 'admin' || role === 'analyst'
  },
  canEdit: () => {
    const role = get().user?.role
    return role === 'admin' || role === 'analyst'
  },
  canCreateScans: () => {
    const role = get().user?.role
    return role === 'admin' || role === 'analyst'
  },
}))

export function AuthProvider({ children }: { children: React.ReactNode }) {
  return <>{children}</>
}
