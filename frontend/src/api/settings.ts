import apiClient from './client'

export interface UserSettings {
  email: string
  full_name?: string
  current_password?: string
  new_password?: string
}

export interface ApiKeySettings {
  anthropic_api_key?: string
  shodan_api_key?: string
  wpscan_api_key?: string
}

export interface NotificationSettings {
  slack_webhook_url?: string
  smtp_host?: string
  smtp_port?: number
  smtp_user?: string
  smtp_password?: string
  notification_email_from?: string
  notification_email_to?: string[]
}

export interface ScanDefaults {
  default_scan_profile: string
  max_concurrent_scans: number
  scan_timeout_hours: number
}

export interface Settings {
  user?: UserSettings
  api_keys?: ApiKeySettings
  notifications?: NotificationSettings
  scan_defaults?: ScanDefaults
}

export const settingsApi = {
  // Get all settings
  getAll: async (): Promise<Settings> => {
    const { data } = await apiClient.get('/api/v1/settings')
    return data
  },

  // Update user settings
  updateUser: async (payload: Partial<UserSettings>): Promise<UserSettings> => {
    const { data } = await apiClient.patch('/api/v1/settings/user', payload)
    return data
  },

  // Update API keys
  updateApiKeys: async (payload: ApiKeySettings): Promise<ApiKeySettings> => {
    const { data } = await apiClient.patch('/api/v1/settings/api-keys', payload)
    return data
  },

  // Update notification settings
  updateNotifications: async (payload: NotificationSettings): Promise<NotificationSettings> => {
    const { data } = await apiClient.patch('/api/v1/settings/notifications', payload)
    return data
  },

  // Update scan defaults
  updateScanDefaults: async (payload: Partial<ScanDefaults>): Promise<ScanDefaults> => {
    const { data } = await apiClient.patch('/api/v1/settings/scan-defaults', payload)
    return data
  },

  // Test Slack notification
  testSlack: async (webhookUrl: string): Promise<{ message: string }> => {
    const { data } = await apiClient.post('/api/v1/settings/notifications/test-slack', {
      webhook_url: webhookUrl,
    })
    return data
  },

  // Test SMTP notification
  testSmtp: async (config: { host: string; port: number; user: string; password?: string }): Promise<{ message: string }> => {
    const { data } = await apiClient.post('/api/v1/settings/notifications/test-smtp', config)
    return data
  },
}
