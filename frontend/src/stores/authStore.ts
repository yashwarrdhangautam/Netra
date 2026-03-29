import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface AuthState {
  token: string | null
  user: { id: string; email: string; is_admin: boolean } | null
  isAuthenticated: boolean
  login: (token: string, user: { id: string; email: string; is_admin: boolean }) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
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
    }),
    { name: 'netra-auth' }
  )
)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  return <>{children}</>
}
