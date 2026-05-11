import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { cn } from '@/utils/formatters'
import {
  Settings as SettingsIcon,
  Key,
  Bell,
  Monitor,
  Info,
  Save,
  Eye,
  EyeOff,
  Github,
  Check,
  AlertCircle,
} from 'lucide-react'

const TABS = [
  { id: 'api-keys', label: 'API Keys', icon: Key },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'scan-defaults', label: 'Scan Defaults', icon: Monitor },
  { id: 'about', label: 'About', icon: Info },
]

const SCAN_PROFILES = [
  { value: 'quick-recon', label: 'Quick Recon' },
  { value: 'standard', label: 'Standard' },
  { value: 'full-pentest', label: 'Full Pentest' },
  { value: 'custom', label: 'Custom' },
]

interface NotificationMessage {
  type: 'success' | 'error'
  text: string
}

interface ScanDefaults {
  profile: string
  maxConcurrentScans: number
  timeout: number
}

interface ApiKeys {
  anthropic: string
  shodan: string
  wpscan: string
}

export function Settings() {
  const [activeTab, setActiveTab] = useState('api-keys')

  // API Keys state
  const [apiKeys, setApiKeys] = useState<ApiKeys>({
    anthropic: '',
    shodan: '',
    wpscan: '',
  })
  const [showApiKeys, setShowApiKeys] = useState<Record<string, boolean>>({
    anthropic: false,
    shodan: false,
    wpscan: false,
  })
  const [apiKeyMessage, setApiKeyMessage] = useState<NotificationMessage | null>(null)

  // Notifications state
  const [slackWebhook, setSlackWebhook] = useState('')
  const [smtpHost, setSmtpHost] = useState('')
  const [smtpPort, setSmtpPort] = useState('587')
  const [smtpUsername, setSmtpUsername] = useState('')
  const [smtpPassword, setSmtpPassword] = useState('')
  const [showSmtpPassword, setShowSmtpPassword] = useState(false)
  const [notificationMessage, setNotificationMessage] = useState<NotificationMessage | null>(null)

  // Scan Defaults state
  const [scanDefaults, setScanDefaults] = useState<ScanDefaults>({
    profile: 'standard',
    maxConcurrentScans: 3,
    timeout: 3600,
  })
  const [scanMessage, setScanMessage] = useState<NotificationMessage | null>(null)

  // API Keys handlers
  const handleApiKeyChange = (key: keyof ApiKeys, value: string) => {
    setApiKeys(prev => ({ ...prev, [key]: value }))
  }

  const handleToggleApiKeyVisibility = (key: string) => {
    setShowApiKeys(prev => ({ ...prev, [key]: !prev[key] }))
  }

  const handleSaveApiKeys = () => {
    // Simulate API call
    setApiKeyMessage({ type: 'success', text: 'API keys saved successfully' })
    setTimeout(() => setApiKeyMessage(null), 3000)
  }

  // Notifications handlers
  const handleTestSlack = () => {
    if (!slackWebhook.trim()) {
      setNotificationMessage({ type: 'error', text: 'Slack webhook URL is required' })
      setTimeout(() => setNotificationMessage(null), 3000)
      return
    }
    // Simulate API call
    setNotificationMessage({ type: 'success', text: 'Test notification sent to Slack' })
    setTimeout(() => setNotificationMessage(null), 3000)
  }

  const handleTestSmtp = () => {
    if (!smtpHost.trim() || !smtpUsername.trim()) {
      setNotificationMessage({ type: 'error', text: 'SMTP host and username are required' })
      setTimeout(() => setNotificationMessage(null), 3000)
      return
    }
    // Simulate API call
    setNotificationMessage({ type: 'success', text: 'Test email sent successfully' })
    setTimeout(() => setNotificationMessage(null), 3000)
  }

  const handleSaveNotifications = () => {
    // Simulate API call
    setNotificationMessage({ type: 'success', text: 'Notification settings saved' })
    setTimeout(() => setNotificationMessage(null), 3000)
  }

  // Scan Defaults handlers
  const handleScanDefaultsChange = (key: keyof ScanDefaults, value: string | number) => {
    setScanDefaults(prev => ({ ...prev, [key]: value }))
  }

  const handleSaveScanDefaults = () => {
    // Simulate API call
    setScanMessage({ type: 'success', text: 'Scan defaults saved successfully' })
    setTimeout(() => setScanMessage(null), 3000)
  }

  return (
    <div className="min-h-screen bg-background p-8">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <SettingsIcon className="w-8 h-8 text-accent" />
            <h1 className="text-3xl font-bold text-foreground">Settings</h1>
          </div>
          <p className="text-foreground-secondary">Configure API keys, notifications, and scan defaults</p>
        </div>

        {/* Tab Navigation */}
        <div className="flex gap-2 mb-8 border-b border-border pb-4">
          {TABS.map(tab => {
            const Icon = tab.icon
            const isActive = activeTab === tab.id
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  'flex items-center gap-2 px-4 py-2 rounded-md font-medium transition-colors',
                  isActive
                    ? 'bg-accent text-white'
                    : 'text-foreground-secondary hover:text-foreground hover:bg-surface-2'
                )}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            )
          })}
        </div>

        {/* Tab Content */}
        <div className="space-y-6">
          {/* API Keys Tab */}
          {activeTab === 'api-keys' && (
            <div className="space-y-6">
              {apiKeyMessage && (
                <div
                  className={cn(
                    'p-4 rounded-md flex items-center gap-2',
                    apiKeyMessage.type === 'success'
                      ? 'bg-green-900/20 text-green-400 border border-green-900/50'
                      : 'bg-red-900/20 text-red-400 border border-red-900/50'
                  )}
                >
                  {apiKeyMessage.type === 'success' ? (
                    <Check className="w-4 h-4" />
                  ) : (
                    <AlertCircle className="w-4 h-4" />
                  )}
                  {apiKeyMessage.text}
                </div>
              )}

              {/* Anthropic API Key */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Key className="w-5 h-5 text-accent" />
                    Anthropic API Key
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p className="text-sm text-foreground-secondary">
                    Required for AI-powered analysis and threat intelligence
                  </p>
                  <div className="relative">
                    <input
                      type={showApiKeys['anthropic'] ? 'text' : 'password'}
                      value={apiKeys.anthropic}
                      onChange={e => handleApiKeyChange('anthropic', e.target.value)}
                      placeholder="sk-ant-..."
                      className="w-full bg-surface-2 text-foreground border border-border rounded-md px-4 py-2 placeholder-foreground-tertiary focus:outline-none focus:ring-2 focus:ring-accent"
                    />
                    <button
                      onClick={() => handleToggleApiKeyVisibility('anthropic')}
                      className="absolute right-3 top-2.5 text-foreground-secondary hover:text-foreground transition-colors"
                    >
                      {showApiKeys['anthropic'] ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </CardContent>
              </Card>

              {/* Shodan API Key */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Key className="w-5 h-5 text-accent" />
                    Shodan API Key
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p className="text-sm text-foreground-secondary">
                    Used for internet-wide vulnerability scanning
                  </p>
                  <div className="relative">
                    <input
                      type={showApiKeys['shodan'] ? 'text' : 'password'}
                      value={apiKeys.shodan}
                      onChange={e => handleApiKeyChange('shodan', e.target.value)}
                      placeholder="Enter your Shodan API key"
                      className="w-full bg-surface-2 text-foreground border border-border rounded-md px-4 py-2 placeholder-foreground-tertiary focus:outline-none focus:ring-2 focus:ring-accent"
                    />
                    <button
                      onClick={() => handleToggleApiKeyVisibility('shodan')}
                      className="absolute right-3 top-2.5 text-foreground-secondary hover:text-foreground transition-colors"
                    >
                      {showApiKeys['shodan'] ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </CardContent>
              </Card>

              {/* WPScan API Key */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Key className="w-5 h-5 text-accent" />
                    WPScan API Key
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p className="text-sm text-foreground-secondary">
                    WordPress vulnerability scanning
                  </p>
                  <div className="relative">
                    <input
                      type={showApiKeys['wpscan'] ? 'text' : 'password'}
                      value={apiKeys.wpscan}
                      onChange={e => handleApiKeyChange('wpscan', e.target.value)}
                      placeholder="Enter your WPScan API key"
                      className="w-full bg-surface-2 text-foreground border border-border rounded-md px-4 py-2 placeholder-foreground-tertiary focus:outline-none focus:ring-2 focus:ring-accent"
                    />
                    <button
                      onClick={() => handleToggleApiKeyVisibility('wpscan')}
                      className="absolute right-3 top-2.5 text-foreground-secondary hover:text-foreground transition-colors"
                    >
                      {showApiKeys['wpscan'] ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </CardContent>
              </Card>

              {/* Save Button */}
              <div className="flex justify-end">
                <Button onClick={handleSaveApiKeys} size="lg" className="gap-2">
                  <Save className="w-4 h-4" />
                  Save API Keys
                </Button>
              </div>
            </div>
          )}

          {/* Notifications Tab */}
          {activeTab === 'notifications' && (
            <div className="space-y-6">
              {notificationMessage && (
                <div
                  className={cn(
                    'p-4 rounded-md flex items-center gap-2',
                    notificationMessage.type === 'success'
                      ? 'bg-green-900/20 text-green-400 border border-green-900/50'
                      : 'bg-red-900/20 text-red-400 border border-red-900/50'
                  )}
                >
                  {notificationMessage.type === 'success' ? (
                    <Check className="w-4 h-4" />
                  ) : (
                    <AlertCircle className="w-4 h-4" />
                  )}
                  {notificationMessage.text}
                </div>
              )}

              {/* Slack Integration */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Bell className="w-5 h-5 text-accent" />
                    Slack Integration
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p className="text-sm text-foreground-secondary">
                    Send scan results and alerts to a Slack channel
                  </p>
                  <input
                    type="text"
                    value={slackWebhook}
                    onChange={e => setSlackWebhook(e.target.value)}
                    placeholder="https://hooks.slack.com/services/..."
                    className="w-full bg-surface-2 text-foreground border border-border rounded-md px-4 py-2 placeholder-foreground-tertiary focus:outline-none focus:ring-2 focus:ring-accent"
                  />
                  <Button
                    variant="outline"
                    onClick={handleTestSlack}
                    className="w-full"
                  >
                    Test Slack Webhook
                  </Button>
                </CardContent>
              </Card>

              {/* Email (SMTP) Integration */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Bell className="w-5 h-5 text-accent" />
                    Email (SMTP) Integration
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p className="text-sm text-foreground-secondary">
                    Send email notifications for scan events
                  </p>

                  <div className="space-y-3">
                    <div>
                      <label className="block text-sm font-medium text-foreground mb-1">
                        SMTP Host
                      </label>
                      <input
                        type="text"
                        value={smtpHost}
                        onChange={e => setSmtpHost(e.target.value)}
                        placeholder="smtp.gmail.com"
                        className="w-full bg-surface-2 text-foreground border border-border rounded-md px-4 py-2 placeholder-foreground-tertiary focus:outline-none focus:ring-2 focus:ring-accent"
                      />
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-foreground mb-1">
                          Port
                        </label>
                        <input
                          type="number"
                          value={smtpPort}
                          onChange={e => setSmtpPort(e.target.value)}
                          placeholder="587"
                          className="w-full bg-surface-2 text-foreground border border-border rounded-md px-4 py-2 placeholder-foreground-tertiary focus:outline-none focus:ring-2 focus:ring-accent"
                        />
                      </div>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-foreground mb-1">
                        Username
                      </label>
                      <input
                        type="text"
                        value={smtpUsername}
                        onChange={e => setSmtpUsername(e.target.value)}
                        placeholder="your-email@example.com"
                        className="w-full bg-surface-2 text-foreground border border-border rounded-md px-4 py-2 placeholder-foreground-tertiary focus:outline-none focus:ring-2 focus:ring-accent"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-foreground mb-1">
                        Password
                      </label>
                      <div className="relative">
                        <input
                          type={showSmtpPassword ? 'text' : 'password'}
                          value={smtpPassword}
                          onChange={e => setSmtpPassword(e.target.value)}
                          placeholder="Enter your password"
                          className="w-full bg-surface-2 text-foreground border border-border rounded-md px-4 py-2 placeholder-foreground-tertiary focus:outline-none focus:ring-2 focus:ring-accent"
                        />
                        <button
                          onClick={() => setShowSmtpPassword(!showSmtpPassword)}
                          className="absolute right-3 top-2.5 text-foreground-secondary hover:text-foreground transition-colors"
                        >
                          {showSmtpPassword ? (
                            <EyeOff className="w-4 h-4" />
                          ) : (
                            <Eye className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>

                  <Button
                    variant="outline"
                    onClick={handleTestSmtp}
                    className="w-full"
                  >
                    Test SMTP Configuration
                  </Button>
                </CardContent>
              </Card>

              {/* Save Button */}
              <div className="flex justify-end">
                <Button onClick={handleSaveNotifications} size="lg" className="gap-2">
                  <Save className="w-4 h-4" />
                  Save Notification Settings
                </Button>
              </div>
            </div>
          )}

          {/* Scan Defaults Tab */}
          {activeTab === 'scan-defaults' && (
            <div className="space-y-6">
              {scanMessage && (
                <div
                  className={cn(
                    'p-4 rounded-md flex items-center gap-2',
                    scanMessage.type === 'success'
                      ? 'bg-green-900/20 text-green-400 border border-green-900/50'
                      : 'bg-red-900/20 text-red-400 border border-red-900/50'
                  )}
                >
                  {scanMessage.type === 'success' ? (
                    <Check className="w-4 h-4" />
                  ) : (
                    <AlertCircle className="w-4 h-4" />
                  )}
                  {scanMessage.text}
                </div>
              )}

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Monitor className="w-5 h-5 text-accent" />
                    Default Scan Configuration
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div>
                    <label className="block text-sm font-medium text-foreground mb-2">
                      Default Scan Profile
                    </label>
                    <select
                      value={scanDefaults.profile}
                      onChange={e =>
                        handleScanDefaultsChange('profile', e.target.value)
                      }
                      className="w-full bg-surface-2 text-foreground border border-border rounded-md px-4 py-2 focus:outline-none focus:ring-2 focus:ring-accent"
                    >
                      {SCAN_PROFILES.map(profile => (
                        <option key={profile.value} value={profile.value}>
                          {profile.label}
                        </option>
                      ))}
                    </select>
                    <p className="text-xs text-foreground-secondary mt-2">
                      {scanDefaults.profile === 'quick-recon' &&
                        'Fast reconnaissance scan focusing on basic vulnerabilities'}
                      {scanDefaults.profile === 'standard' &&
                        'Comprehensive scan with moderate depth and duration'}
                      {scanDefaults.profile === 'full-pentest' &&
                        'Thorough penetration test with all available tools'}
                      {scanDefaults.profile === 'custom' &&
                        'Custom configuration tailored to your needs'}
                    </p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-foreground mb-2">
                      Maximum Concurrent Scans
                    </label>
                    <input
                      type="number"
                      min="1"
                      max="10"
                      value={scanDefaults.maxConcurrentScans}
                      onChange={e =>
                        handleScanDefaultsChange(
                          'maxConcurrentScans',
                          parseInt(e.target.value)
                        )
                      }
                      className="w-full bg-surface-2 text-foreground border border-border rounded-md px-4 py-2 focus:outline-none focus:ring-2 focus:ring-accent"
                    />
                    <p className="text-xs text-foreground-secondary mt-2">
                      Number of scans that can run simultaneously (1-10)
                    </p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-foreground mb-2">
                      Scan Timeout (seconds)
                    </label>
                    <input
                      type="number"
                      min="300"
                      step="300"
                      value={scanDefaults.timeout}
                      onChange={e =>
                        handleScanDefaultsChange(
                          'timeout',
                          parseInt(e.target.value)
                        )
                      }
                      className="w-full bg-surface-2 text-foreground border border-border rounded-md px-4 py-2 focus:outline-none focus:ring-2 focus:ring-accent"
                    />
                    <p className="text-xs text-foreground-secondary mt-2">
                      Maximum duration for a single scan in seconds (~
                      {Math.floor(scanDefaults.timeout / 60)} minutes)
                    </p>
                  </div>
                </CardContent>
              </Card>

              {/* Save Button */}
              <div className="flex justify-end">
                <Button onClick={handleSaveScanDefaults} size="lg" className="gap-2">
                  <Save className="w-4 h-4" />
                  Save Scan Defaults
                </Button>
              </div>
            </div>
          )}

          {/* About Tab */}
          {activeTab === 'about' && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Info className="w-5 h-5 text-accent" />
                    About NETRA
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <span className="text-foreground-secondary">Version</span>
                      <Badge variant="default">1.0.0</Badge>
                    </div>

                    <div className="flex justify-between items-center">
                      <span className="text-foreground-secondary">License</span>
                      <Badge variant="secondary">AGPL-3.0</Badge>
                    </div>

                    <div className="border-t border-border pt-4">
                      <p className="text-sm text-foreground-secondary mb-4">
                        NETRA is an AI-augmented unified cybersecurity platform
                        that combines multiple security scanners with advanced AI
                        analysis to provide comprehensive threat intelligence and
                        vulnerability assessment.
                      </p>
                      <p className="text-sm text-foreground-secondary">
                        This software is distributed under the GNU Affero General
                        Public License v3.0 (AGPL-3.0). You are free to use,
                        modify, and distribute this software under the terms of
                        the AGPL-3.0 license.
                      </p>
                    </div>

                    <div className="flex gap-3 pt-4 border-t border-border">
                      <a
                        href="https://github.com/netra/netra"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-surface-2 hover:bg-surface-3 text-foreground transition-colors"
                      >
                        <Github className="w-4 h-4" />
                        View on GitHub
                      </a>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>System Information</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-foreground-secondary">Platform</span>
                    <span className="text-foreground">Python 3.12 + React 18</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-foreground-secondary">API Version</span>
                    <span className="text-foreground">v1</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-foreground-secondary">Database</span>
                    <span className="text-foreground">PostgreSQL / SQLite</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-foreground-secondary">AI Engine</span>
                    <span className="text-foreground">Claude Agent SDK</span>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
