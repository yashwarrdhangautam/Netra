import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios'

const API_BASE_URL = (import.meta as any).env?.VITE_API_URL || '/api'

// Create axios instance
export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Send cookies with requests
  timeout: 30000,
})

// Request interceptor to add CSRF token
apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    // Get CSRF token from cookie
    const csrfToken = getCookie('csrf_token')
    if (csrfToken && config.headers) {
      config.headers['X-CSRF-Token'] = csrfToken
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      // Token expired or invalid - clear auth state
      window.location.href = '/login'
    }
    if (error.response?.status === 403 && (error.response?.data as Record<string, string>)?.detail?.includes('CSRF')) {
      // CSRF token mismatch - reload to get new token
      console.error('CSRF token mismatch, reloading...')
      window.location.reload()
    }
    return Promise.reject(error)
  }
)

// Helper function to get cookie value
function getCookie(name: string): string | null {
  const value = `; ${document.cookie}`
  const parts = value.split(`; ${name}=`)
  if (parts.length === 2) {
    return parts.pop()?.split(';').shift() || null
  }
  return null
}

export default apiClient
