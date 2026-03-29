import apiClient from './client'
import type { ComplianceScore } from '@/types'

export interface Framework {
  id: string
  name: string
  description: string
  total_controls: number
}

export const complianceApi = {
  getFrameworks: async (): Promise<Framework[]> => {
    const { data } = await apiClient.get('/api/v1/compliance/frameworks')
    return data
  },

  getComplianceScore: async (scanId: string, framework: string): Promise<ComplianceScore> => {
    const { data } = await apiClient.get<ComplianceScore>(`/api/v1/compliance/${scanId}/score/${framework}`)
    return data
  },

  getControlDetails: async (scanId: string, framework: string) => {
    const { data } = await apiClient.get(`/api/v1/compliance/${scanId}/framework/${framework}`)
    return data
  },

  mapFindings: async (scanId: string, frameworks?: string[]) => {
    const { data } = await apiClient.post('/api/v1/compliance/map', {
      scan_id: scanId,
      frameworks,
    })
    return data
  },
}
