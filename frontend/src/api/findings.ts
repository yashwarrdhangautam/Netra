import apiClient from './client'
import type { PaginatedResponse, Finding, FindingStatus, Severity } from '@/types'

export interface CreateFindingPayload {
  scan_id: string
  title: string
  description: string
  severity: Severity
  tool_source: string
  cwe_id?: string | null
  url?: string | null
  evidence?: Record<string, unknown> | null
}

export interface FindingFilters {
  page?: number
  per_page?: number
  severity?: Severity
  status?: FindingStatus
  scan_id?: string
}

export const findingsApi = {
  /** List findings with pagination and filters */
  list: async (filters?: FindingFilters): Promise<PaginatedResponse<FindingList>> => {
    const { data } = await apiClient.get<PaginatedResponse<FindingList>>('/api/v1/findings', { params: filters })
    return data
  },

  /** Get finding details by ID */
  get: async (findingId: string): Promise<Finding> => {
    const { data } = await apiClient.get<Finding>(`/api/v1/findings/${findingId}`)
    return data
  },

  /** Create a new finding */
  create: async (payload: CreateFindingPayload): Promise<Finding> => {
    const { data } = await apiClient.post<Finding>('/api/v1/findings/', payload)
    return data
  },

  /** Update a finding */
  update: async (findingId: string, payload: Partial<Finding>): Promise<Finding> => {
    const { data } = await apiClient.patch<Finding>(`/api/v1/findings/${findingId}`, payload)
    return data
  },

  /** Delete a finding */
  delete: async (findingId: string): Promise<void> => {
    await apiClient.delete(`/api/v1/findings/${findingId}`)
  },

  /** Mark finding as false positive */
  markFalsePositive: async (findingId: string): Promise<Finding> => {
    const { data } = await apiClient.post<Finding>(`/api/v1/findings/${findingId}/mark-false-positive`)
    return data
  },

  /** Bulk update findings */
  bulkUpdate: async (findingIds: string[], payload: {
    status?: FindingStatus
    severity?: Severity
    assignee?: string
    tags?: string[]
  }): Promise<{ updated_count: number }> => {
    const { data } = await apiClient.post('/api/v1/findings/bulk-update', {
      finding_ids: findingIds,
      ...payload,
    })
    return data
  },
}
