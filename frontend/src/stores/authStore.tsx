import { create } from 'zustand'
import { persist } from 'zustand/middleware'

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
  token: string | null
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

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      token: null,
      user: null,
      isAuthenticated: false,
      login: (token, user) => {
        localStorage.setItem('netra_token', token)
        set({ token, user, isAuthenticated: true })
      },
      logout: () => {
        localStorage.removeItem('netra_token')
        set({ token: null, user: null, isAuthenticated: false })
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
    }),
    { name: 'netra-auth' }
  )
)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  return <>{children}</>
}
