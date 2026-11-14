import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { NotificationBanner, type BannerMessage } from '@/components/shared/NotificationBanner'
import { accountApi, settingsApi, type IntegrationStatus } from '@/api/platform'
import { useAuthStore } from '@/stores/authStore'
import { validatePasswordLocally } from '@/utils/passwordPolicy'
import { ScannerToolsCard } from '@/components/settings/ScannerToolsCard'

const INPUT =
  'w-full rounded border border-border bg-surface-2 p-2 text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary disabled:opacity-50'

type Tab = 'account' | 'integrations' | 'notifications'

function errorText(err: unknown, fallback: string): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

export function Settings() {
  const [tab, setTab] = useState<Tab>('account')
  const isAdmin = useAuthStore((s) => s.isAdmin)()

  const tabs: { id: Tab; label: string; adminOnly?: boolean }[] = [
    { id: 'account', label: 'Account' },
    { id: 'integrations', label: 'Integrations', adminOnly: true },
    { id: 'notifications', label: 'Notifications' },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Settings</h1>
        <p className="text-sm text-muted-foreground">
          Your account, integration keys and notification checks.
        </p>
      </div>

      <div role="tablist" className="flex gap-2 border-b border-border">
        {tabs
          .filter((t) => !t.adminOnly || isAdmin)
          .map((t) => (
            <button
              key={t.id}
              role="tab"
              aria-selected={tab === t.id}
              onClick={() => setTab(t.id)}
              className={
                tab === t.id
                  ? 'border-b-2 border-accent px-3 py-2 text-sm font-medium text-foreground'
                  : 'px-3 py-2 text-sm text-muted-foreground hover:text-foreground'
              }
            >
              {t.label}
            </button>
          ))}
      </div>

      {tab === 'account' && <AccountTab />}
      {tab === 'integrations' && isAdmin && (
        <div className="space-y-6">
          <IntegrationsTab />
          <ScannerToolsCard />
        </div>
      )}
      {tab === 'notifications' && <NotificationsTab isAdmin={isAdmin} />}
    </div>
  )
}

// ── Account: password, MFA, personal API key ──────────────────────────────────

function AccountTab() {
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <PasswordCard />
      <MfaCard />
      <ApiKeyCard />
    </div>
  )
}

function PasswordCard() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<BannerMessage | null>(null)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const problem = validatePasswordLocally(next)
    if (problem) return setMessage({ type: 'error', text: problem })
    if (next !== confirm) return setMessage({ type: 'error', text: 'The new passwords do not match.' })
    setBusy(true)
    try {
      await accountApi.changePassword(current, next)
      setCurrent('')
      setNext('')
      setConfirm('')
      setMessage({ type: 'success', text: 'Password changed.' })
    } catch (err) {
      setMessage({ type: 'error', text: errorText(err, 'Could not change the password.') })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Change password</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-3">
          <input type="password" aria-label="Current password" placeholder="Current password"
            value={current} onChange={(e) => setCurrent(e.target.value)} className={INPUT} required />
          <input type="password" aria-label="New password" placeholder="New password (12+ characters)"
            value={next} onChange={(e) => setNext(e.target.value)} className={INPUT} required />
          <input type="password" aria-label="Repeat new password" placeholder="Repeat new password"
            value={confirm} onChange={(e) => setConfirm(e.target.value)} className={INPUT} required />
          <Button type="submit" disabled={busy}>Change password</Button>
        </form>
        <div className="mt-3">
          <NotificationBanner message={message} onDismiss={() => setMessage(null)} />
        </div>
      </CardContent>
    </Card>
  )
}

function MfaCard() {
  const queryClient = useQueryClient()
  const { data: status, refetch } = useQuery({ queryKey: ['mfa-status'], queryFn: accountApi.mfaStatus })
  const [setup, setSetup] = useState<{ secret: string; provisioning_uri: string } | null>(null)
  const [code, setCode] = useState('')
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null)
  const [message, setMessage] = useState<BannerMessage | null>(null)

  const start = async () => {
    try {
      setSetup(await accountApi.mfaSetup())
      setMessage(null)
    } catch (err) {
      setMessage({ type: 'error', text: errorText(err, 'Could not start MFA setup.') })
    }
  }

  const enable = async () => {
    try {
      const result = await accountApi.mfaEnable(code.trim())
      setBackupCodes(result.backup_codes)
      setSetup(null)
      setCode('')
      await refetch()
      await queryClient.invalidateQueries({ queryKey: ['mfa-status'] })
      setMessage({ type: 'success', text: 'MFA is on. Save the backup codes now; they are shown once.' })
    } catch (err) {
      setMessage({ type: 'error', text: errorText(err, 'That code did not match.') })
    }
  }

  const disable = async () => {
    try {
      await accountApi.mfaDisable(code.trim())
      setCode('')
      setBackupCodes(null)
      await refetch()
      setMessage({ type: 'success', text: 'MFA is off.' })
    } catch (err) {
      setMessage({ type: 'error', text: errorText(err, 'That code did not match.') })
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Two-factor sign-in (MFA)</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          Status:{' '}
          <span className="font-medium text-foreground">{status?.enabled ? 'On' : 'Off'}</span>
          {status?.enabled && ` · ${status.backup_codes_remaining} backup codes left`}
        </p>

        {!status?.enabled && !setup && (
          <Button onClick={start}>Set up authenticator app</Button>
        )}

        {setup && (
          <div className="space-y-2 rounded border border-border p-3">
            <p>Add this key to your authenticator app, then enter the 6-digit code it shows.</p>
            <code className="block break-all rounded bg-surface-2 p-2 text-xs">{setup.secret}</code>
            <input aria-label="Authenticator code" inputMode="numeric" placeholder="123456"
              value={code} onChange={(e) => setCode(e.target.value)} className={INPUT} />
            <Button onClick={enable} disabled={!code.trim()}>Turn on MFA</Button>
          </div>
        )}

        {status?.enabled && (
          <div className="space-y-2">
            <input aria-label="Current authenticator code" inputMode="numeric"
              placeholder="Current code to turn off MFA" value={code}
              onChange={(e) => setCode(e.target.value)} className={INPUT} />
            <Button variant="destructive" onClick={disable} disabled={!code.trim()}>
              Turn off MFA
            </Button>
          </div>
        )}

        {backupCodes && (
          <div className="rounded border border-yellow-700 bg-yellow-900/20 p-3">
            <p className="mb-2 font-medium text-yellow-300">Backup codes (each works once)</p>
            <div className="grid grid-cols-2 gap-1 font-mono text-xs">
              {backupCodes.map((c) => <span key={c}>{c}</span>)}
            </div>
          </div>
        )}

        <NotificationBanner message={message} onDismiss={() => setMessage(null)} />
      </CardContent>
    </Card>
  )
}

function ApiKeyCard() {
  const { data: status, refetch } = useQuery({ queryKey: ['api-key-status'], queryFn: accountApi.apiKeyStatus })
  const [newKey, setNewKey] = useState<string | null>(null)
  const [message, setMessage] = useState<BannerMessage | null>(null)

  const create = async () => {
    try {
      const result = await accountApi.apiKeyCreate()
      setNewKey(result.api_key)
      await refetch()
      setMessage({ type: 'success', text: 'New key created. Copy it now; it is not shown again.' })
    } catch (err) {
      setMessage({ type: 'error', text: errorText(err, 'Could not create a key.') })
    }
  }

  const revoke = async () => {
    try {
      await accountApi.apiKeyRevoke()
      setNewKey(null)
      await refetch()
      setMessage({ type: 'success', text: 'API key revoked.' })
    } catch (err) {
      setMessage({ type: 'error', text: errorText(err, 'Could not revoke the key.') })
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Personal API key</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          For scripts and MCP clients. Send it as <code>Authorization: Bearer &lt;key&gt;</code>.
          Creating a new key replaces the old one.
        </p>
        <div className="flex gap-2">
          <Button onClick={create}>{status?.has_key ? 'Replace key' : 'Create key'}</Button>
          {status?.has_key && (
            <Button variant="destructive" onClick={revoke}>Revoke</Button>
          )}
        </div>
        {newKey && (
          <code className="block break-all rounded bg-surface-2 p-2 text-xs" data-testid="new-api-key">
            {newKey}
          </code>
        )}
        <NotificationBanner message={message} onDismiss={() => setMessage(null)} />
      </CardContent>
    </Card>
  )
}

// ── Integrations (admin): keys are encrypted at rest and shown masked ─────────

function IntegrationsTab() {
  const queryClient = useQueryClient()
  const { data: items = [], isLoading } = useQuery({
    queryKey: ['integrations'],
    queryFn: settingsApi.integrations,
  })
  const [message, setMessage] = useState<BannerMessage | null>(null)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Integration keys</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Keys entered here are encrypted on the server. Values are never shown again after saving.
          A key set in the server environment is used when nothing is saved here.
        </p>
        {isLoading && <p className="text-sm text-muted-foreground">Loading…</p>}
        {items.map((item) => (
          <IntegrationRow
            key={item.name}
            item={item}
            onChanged={async (text) => {
              await queryClient.invalidateQueries({ queryKey: ['integrations'] })
              setMessage({ type: 'success', text })
            }}
            onError={(text) => setMessage({ type: 'error', text })}
          />
        ))}
        <NotificationBanner message={message} onDismiss={() => setMessage(null)} />
      </CardContent>
    </Card>
  )
}

function IntegrationRow({
  item,
  onChanged,
  onError,
}: {
  item: IntegrationStatus
  onChanged: (text: string) => Promise<void>
  onError: (text: string) => void
}) {
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)

  const save = async () => {
    setBusy(true)
    try {
      await settingsApi.setIntegration(item.name, value)
      setValue('')
      await onChanged(`${item.label} saved.`)
    } catch (err) {
      onError(errorText(err, `Could not save ${item.label}.`))
    } finally {
      setBusy(false)
    }
  }

  const clear = async () => {
    setBusy(true)
    try {
      await settingsApi.setIntegration(item.name, '')
      await onChanged(`${item.label} cleared.`)
    } catch (err) {
      onError(errorText(err, `Could not clear ${item.label}.`))
    } finally {
      setBusy(false)
    }
  }

  const sourceLabel =
    item.source === 'gui' ? 'set here' : item.source === 'environment' ? 'set on the server' : 'not set'

  return (
    <div className="space-y-2 rounded border border-border p-3">
      <div className="flex items-center justify-between text-sm">
        <span className="font-medium text-foreground">{item.label}</span>
        <span className="text-muted-foreground">
          {item.configured ? `${item.masked} (${sourceLabel})` : 'Not set'}
        </span>
      </div>
      <div className="flex gap-2">
        <input
          type="password"
          aria-label={`New ${item.label}`}
          placeholder={item.configured ? 'Enter a new value to replace' : 'Enter value'}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          className={INPUT}
          autoComplete="off"
        />
        <Button onClick={save} disabled={busy || !value.trim()}>Save</Button>
        {item.source === 'gui' && (
          <Button variant="destructive" onClick={clear} disabled={busy}>Clear</Button>
        )}
      </div>
    </div>
  )
}

// ── Notifications: real test sends, honest about missing configuration ───────

function NotificationsTab({ isAdmin }: { isAdmin: boolean }) {
  const [slack, setSlack] = useState<BannerMessage | null>(null)
  const [email, setEmail] = useState<BannerMessage | null>(null)
  const [busy, setBusy] = useState<'slack' | 'email' | null>(null)

  const sendSlack = async () => {
    setBusy('slack')
    try {
      const result = await settingsApi.testSlack()
      setSlack({ type: result.sent ? 'success' : 'error', text: result.detail })
    } catch (err) {
      setSlack({ type: 'error', text: errorText(err, 'Slack test failed.') })
    } finally {
      setBusy(null)
    }
  }

  const sendEmail = async () => {
    setBusy('email')
    try {
      const result = await settingsApi.testEmail()
      setEmail({ type: result.sent ? 'success' : 'error', text: result.detail })
    } catch (err) {
      setEmail({ type: 'error', text: errorText(err, 'Email test failed.') })
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Slack</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p className="text-muted-foreground">Sends a test message to the saved webhook.</p>
          <Button onClick={sendSlack} disabled={!isAdmin || busy !== null}>
            Send Slack test
          </Button>
          {!isAdmin && <p className="text-xs text-muted-foreground">Admins can send this test.</p>}
          <NotificationBanner message={slack} onDismiss={() => setSlack(null)} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Email</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p className="text-muted-foreground">
            Sends a test email to your address using the server's SMTP settings.
          </p>
          <Button onClick={sendEmail} disabled={busy !== null}>Send email test</Button>
          <NotificationBanner message={email} onDismiss={() => setEmail(null)} />
        </CardContent>
      </Card>
    </div>
  )
}
