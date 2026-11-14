// Client functions for account, users, settings, search, audit, schedules and report files.
import apiClient from './client'

export type Role = 'admin' | 'analyst' | 'viewer' | 'client'

export interface AccountMfaStatus {
  enabled: boolean
  backup_codes_remaining: number
}

export interface MfaSetup {
  secret: string
  provisioning_uri: string
}

export interface ManagedUser {
  id: string
  email: string
  full_name: string | null
  role: Role
  is_active: boolean
  is_verified: boolean
  mfa_enabled: boolean
  last_login_at: string | null
}

export interface IntegrationStatus {
  name: string
  label: string
  configured: boolean
  masked: string | null
  source: 'gui' | 'environment' | 'unset'
}

export interface TestResult {
  sent: boolean
  detail: string
}

export interface SearchResults {
  findings: { id: string; title: string; severity: string }[]
  scans: { id: string; name: string; status: string }[]
  targets: { id: string; name: string; value: string }[]
}

export interface AuditEntry {
  id: string
  created_at: string
  actor_email: string | null
  action: string
  resource_type: string
  resource_id: string | null
  detail: Record<string, unknown> | null
}

export interface ScheduleItem {
  id: string
  name: string
  description: string | null
  schedule_type: 'cron' | 'interval' | 'once' | string
  target_id: string
  profile: string
  is_active: boolean
  last_run_at: string | null
  next_run_at: string | null
  total_runs: number
  created_at: string
}

export const accountApi = {
  changePassword: async (current_password: string, new_password: string): Promise<void> => {
    await apiClient.post('/api/v1/auth/change-password', { current_password, new_password })
  },
  mfaStatus: async (): Promise<AccountMfaStatus> => (await apiClient.get('/api/v1/auth/mfa')).data,
  mfaSetup: async (): Promise<MfaSetup> => (await apiClient.post('/api/v1/auth/mfa/setup')).data,
  mfaEnable: async (code: string): Promise<{ enabled: boolean; backup_codes: string[] }> =>
    (await apiClient.post('/api/v1/auth/mfa/enable', { code })).data,
  mfaDisable: async (code: string): Promise<void> => {
    await apiClient.post('/api/v1/auth/mfa/disable', { code })
  },
  apiKeyStatus: async (): Promise<{ has_key: boolean }> => (await apiClient.get('/api/v1/auth/api-key')).data,
  apiKeyCreate: async (): Promise<{ api_key: string; note: string }> =>
    (await apiClient.post('/api/v1/auth/api-key')).data,
  apiKeyRevoke: async (): Promise<void> => {
    await apiClient.delete('/api/v1/auth/api-key')
  },
  logout: async (): Promise<void> => {
    try {
      await apiClient.post('/api/v1/auth/logout')
    } catch {
      // Clearing local state still signs the user out if the server call fails.
    }
  },
}

export const usersApi = {
  list: async (): Promise<ManagedUser[]> => (await apiClient.get('/api/v1/auth/users')).data,
  create: async (body: {
    email: string
    password: string
    full_name?: string
    role: Role
  }): Promise<ManagedUser> => (await apiClient.post('/api/v1/auth/users', body)).data,
  update: async (
    id: string,
    body: Partial<Pick<ManagedUser, 'role' | 'is_active' | 'full_name'>>
  ): Promise<ManagedUser> => (await apiClient.patch(`/api/v1/auth/users/${id}`, body)).data,
  resetPassword: async (id: string, password: string): Promise<void> => {
    await apiClient.post(`/api/v1/auth/users/${id}/reset-password`, { password })
  },
  deactivate: async (id: string): Promise<void> => {
    await apiClient.delete(`/api/v1/auth/users/${id}`)
  },
}

export const settingsApi = {
  integrations: async (): Promise<IntegrationStatus[]> =>
    (await apiClient.get('/api/v1/settings/integrations')).data,
  setIntegration: async (name: string, value: string): Promise<IntegrationStatus> =>
    (await apiClient.put(`/api/v1/settings/integrations/${name}`, { value })).data,
  testSlack: async (): Promise<TestResult> =>
    (await apiClient.post('/api/v1/settings/notifications/slack/test')).data,
  testEmail: async (): Promise<TestResult> =>
    (await apiClient.post('/api/v1/settings/notifications/email/test')).data,
}

export const searchApi = {
  query: async (q: string): Promise<SearchResults> =>
    (await apiClient.get('/api/v1/search', { params: { q } })).data,
}

export const auditApi = {
  list: async (params: { limit?: number; offset?: number; action?: string }) =>
    (await apiClient.get<{ items: AuditEntry[]; total: number }>('/api/v1/audit', { params })).data,
}

export const targetsExtraApi = {
  update: async (id: string, body: Record<string, unknown>) =>
    (await apiClient.patch(`/api/v1/targets/${id}`, body)).data,
  groups: async (): Promise<string[]> => (await apiClient.get('/api/v1/targets/groups')).data,
  clients: async (): Promise<{ id: string; email: string; full_name: string | null }[]> =>
    (await apiClient.get('/api/v1/targets/clients')).data,
}

export const reportFilesApi = {
  list: async (limit = 100) =>
    (await apiClient.get<Array<Record<string, unknown>>>('/api/v1/reports/', { params: { limit } })).data,
  download: async (reportId: string, filename: string): Promise<void> => {
    const response = await apiClient.get(`/api/v1/reports/${reportId}/download`, {
      responseType: 'blob',
    })
    const url = URL.createObjectURL(response.data)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
  },
}

export const schedulesApi = {
  list: async (): Promise<ScheduleItem[]> =>
    (await apiClient.get('/api/v1/schedules/schedules')).data,
  createCron: async (body: {
    name: string
    target_id: string
    cron_expression: string
    profile: string
  }): Promise<ScheduleItem> => (await apiClient.post('/api/v1/schedules/schedules/cron', body)).data,
  createInterval: async (body: {
    name: string
    target_id: string
    interval_seconds: number
    profile: string
  }): Promise<ScheduleItem> => (await apiClient.post('/api/v1/schedules/schedules/interval', body)).data,
  createOnce: async (body: {
    name: string
    target_id: string
    scheduled_at: string
    profile: string
  }): Promise<ScheduleItem> => (await apiClient.post('/api/v1/schedules/schedules/once', body)).data,
  remove: async (id: string): Promise<void> => {
    await apiClient.delete(`/api/v1/schedules/schedules/${id}`)
  },
  activate: async (id: string): Promise<void> => {
    await apiClient.post(`/api/v1/schedules/schedules/${id}/activate`)
  },
  deactivate: async (id: string): Promise<void> => {
    await apiClient.post(`/api/v1/schedules/schedules/${id}/deactivate`)
  },
  runNow: async (id: string): Promise<void> => {
    await apiClient.post(`/api/v1/schedules/schedules/${id}/run`)
  },
}

export interface ScannerToolRow {
  binary: string
  label: string
  category: string
  optional: boolean
  installed: boolean
  path: string | null
  install_hint: string
}

export interface ScannerToolsResponse {
  tools: ScannerToolRow[]
  missing_required: string[]
  missing_count: number
}

export const scannerApi = {
  tools: async (): Promise<ScannerToolsResponse> =>
    (await apiClient.get('/api/v1/scanner/tools')).data,
}
