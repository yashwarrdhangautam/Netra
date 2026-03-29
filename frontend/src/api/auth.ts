import apiClient from './client'

interface LoginRequest {
  email: string
  password: string
}

interface RegisterRequest {
  email: string
  password: string
  fullName: string
}

interface User {
  id: string
  email: string
  is_admin: boolean
}

export const authApi = {
  login: async (email: string, password: string): Promise<{ token: string; user: User }> => {
    const { data } = await apiClient.post('/api/v1/auth/login', { email, password })
    if (data.access_token) {
      localStorage.setItem('netra_token', data.access_token)
    }
    return data
  },

  register: async (email: string, password: string, fullName: string): Promise<{ token: string; user: User }> => {
    const { data } = await apiClient.post('/api/v1/auth/register', { email, password, full_name: fullName })
    if (data.access_token) {
      localStorage.setItem('netra_token', data.access_token)
    }
    return data
  },

  refreshToken: async (): Promise<{ access_token: string }> => {
    const { data } = await apiClient.post('/api/v1/auth/refresh')
    return data
  },

  getCurrentUser: async (): Promise<User> => {
    const { data } = await apiClient.get('/api/v1/auth/me')
    return data
  },

  logout: (): void => {
    localStorage.removeItem('netra_token')
  },
}
