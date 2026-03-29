import apiClient from './client'
import type { PaginatedResponse, Scan, ScanList, ScanStatus, ScanProfile } from '@/types'

export interface CreateScanPayload {
  target_id: string
  name: string
  profile: ScanProfile
  config?: Record<string, unknown>
}

export interface ScanFilters {
  page?: number
  per_page?: number
  status?: ScanStatus
  profile?: ScanProfile
}

export const scansApi = {
  /** List all scans with pagination and filters */
  list: async (filters?: ScanFilters): Promise<PaginatedResponse<ScanList>> => {
    const { data } = await apiClient.get<PaginatedResponse<ScanList>>('/api/v1/scans', { params: filters })
    return data
  },

  /** Get scan details by ID */
  get: async (scanId: string): Promise<Scan> => {
    const { data } = await apiClient.get<Scan>(`/api/v1/scans/${scanId}`)
    return data
  },

  /** Create a new scan */
  create: async (payload: CreateScanPayload): Promise<Scan> => {
    const { data } = await apiClient.post<Scan>('/api/v1/scans/', payload)
    return data
  },

  /** Update scan (pause, resume, cancel) */
  update: async (scanId: string, payload: Partial<Scan>): Promise<Scan> => {
    const { data } = await apiClient.patch<Scan>(`/api/v1/scans/${scanId}`, payload)
    return data
  },

  /** Delete a scan */
  delete: async (scanId: string): Promise<void> => {
    await apiClient.delete(`/api/v1/scans/${scanId}`)
  },

  /** Get scan phases */
  getPhases: async (scanId: string) => {
    const { data } = await apiClient.get(`/api/v1/scans/${scanId}/phases`)
    return data
  },

  /** Resume a paused/failed scan */
  resume: async (scanId: string): Promise<Scan> => {
    const { data } = await apiClient.post<Scan>(`/api/v1/scans/${scanId}/resume`)
    return data
  },

  /** Compare two scans */
  diff: async (scanAId: string, scanBId: string) => {
    const { data } = await apiClient.post('/api/v1/scans/diff', {
      scan_a_id: scanAId,
      scan_b_id: scanBId,
    })
    return data
  },
}
