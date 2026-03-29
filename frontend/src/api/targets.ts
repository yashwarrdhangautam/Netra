import apiClient from './client'
import type { PaginatedResponse, Target } from '@/types'

export interface CreateTargetPayload {
  name: string
  target_type: 'domain' | 'ip' | 'url' | 'ip_range' | 'domain_list'
  value: string
}

export interface TargetFilters {
  page?: number
  per_page?: number
}

export const targetsApi = {
  list: async (filters?: TargetFilters): Promise<PaginatedResponse<Target>> => {
    const { data } = await apiClient.get<PaginatedResponse<Target>>('/api/v1/targets', { params: filters })
    return data
  },

  get: async (targetId: string): Promise<Target> => {
    const { data } = await apiClient.get<Target>(`/api/v1/targets/${targetId}`)
    return data
  },

  create: async (payload: CreateTargetPayload): Promise<Target> => {
    const { data } = await apiClient.post<Target>('/api/v1/targets/', payload)
    return data
  },

  update: async (targetId: string, payload: Partial<CreateTargetPayload>): Promise<Target> => {
    const { data } = await apiClient.patch<Target>(`/api/v1/targets/${targetId}`, payload)
    return data
  },

  delete: async (targetId: string): Promise<void> => {
    await apiClient.delete(`/api/v1/targets/${targetId}`)
  },

  importTargets: async (file: File): Promise<{ imported: number; failed: number }> => {
    const formData = new FormData()
    formData.append('file', file)
    const { data } = await apiClient.post('/api/v1/targets/import', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data
  },
}
