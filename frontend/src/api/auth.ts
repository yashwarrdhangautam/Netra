import apiClient from './client'

export interface LoginRequest {
  email: string
  password: string
}

export interface RegisterRequest {
  email: string
  password: string
  full_name: string
}

export interface AuthUser {
  id: string
  email: string
  full_name?: string
  role: string
  is_active: boolean
}

export interface LoginResponse {
  access_token: string
  token_type: string
  expires_in: number
}

export const authApi = {
  login: async (email: string, password: string): Promise<LoginResponse> => {
    const { data } = await apiClient.post('/api/v1/auth/login', { email, password })
    if (data.access_token) {
      localStorage.setItem('netra_token', data.access_token)
    }
    return data
  },

  register: async (email: string, password: string, full_name: string): Promise<AuthUser> => {
    const { data } = await apiClient.post('/api/v1/auth/register', { email, password, full_name })
    if (data.access_token) {
      localStorage.setItem('netra_token', data.access_token)
    }
    return data
  },

  refreshToken: async (): Promise<{ access_token: string }> => {
    const { data } = await apiClient.post('/api/v1/auth/refresh')
    return data
  },

  getCurrentUser: async (): Promise<AuthUser> => {
    const { data } = await apiClient.get('/api/v1/auth/me')
    return data
  },

  logout: (): void => {
    localStorage.removeItem('netra_token')
  },
}
