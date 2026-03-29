import apiClient from './client'
import type { Report, ComplianceScore } from '@/types'

export type ReportType = 
  | 'executive' 
  | 'technical' 
  | 'pentest' 
  | 'html' 
  | 'excel' 
  | 'evidence' 
  | 'delta' 
  | 'api' 
  | 'cloud' 
  | 'compliance' 
  | 'full'

export const reportsApi = {
  /** Generate a report for a scan */
  generate: async (scanId: string, reportType: ReportType, framework?: string): Promise<Report> => {
    const { data } = await apiClient.post<Report>(`/api/v1/reports/${scanId}/generate`, null, {
      params: { report_type: reportType, framework },
    })
    return data
  },

  /** Get report details */
  get: async (reportId: string): Promise<Report> => {
    const { data } = await apiClient.get<Report>(`/api/v1/reports/${reportId}`)
    return data
  },

  /** List reports for a scan */
  listForScan: async (scanId: string): Promise<Report[]> => {
    const { data } = await apiClient.get<Report[]>(`/api/v1/reports/scan/${scanId}`)
    return data
  },

  /** Delete a report */
  delete: async (reportId: string): Promise<void> => {
    await apiClient.delete(`/api/v1/reports/${reportId}`)
  },
}

export const complianceApi = {
  /** Get compliance score for a framework */
  getScore: async (scanId: string, framework: string): Promise<ComplianceScore> => {
    const { data } = await apiClient.get<ComplianceScore>(
      `/api/v1/compliance/${scanId}/score/${framework}`
    )
    return data
  },

  /** Get framework status */
  getFrameworkStatus: async (scanId: string, framework: string) => {
    const { data } = await apiClient.get(`/api/v1/compliance/${scanId}/framework/${framework}`)
    return data
  },

  /** Get gap analysis */
  getGapAnalysis: async (scanId: string, framework: string) => {
    const { data } = await apiClient.get(`/api/v1/compliance/${scanId}/gap-analysis/${framework}`)
    return data
  },

  /** Map findings to compliance frameworks */
  mapFindings: async (scanId: string, frameworks?: string[]) => {
    const { data } = await apiClient.post('/api/v1/compliance/map', {
      scan_id: scanId,
      frameworks,
    })
    return data
  },
}
