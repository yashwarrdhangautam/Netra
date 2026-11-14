import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/Button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table'
import { Badge } from '@/components/ui/Badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { NotificationBanner, type BannerMessage } from '@/components/shared/NotificationBanner'
import { usersApi, type ManagedUser, type Role } from '@/api/platform'
import { useAuthStore } from '@/stores/authStore'
import { validatePasswordLocally } from '@/utils/passwordPolicy'

const ROLES: Role[] = ['admin', 'analyst', 'viewer', 'client']
const INPUT =
  'w-full rounded border border-border bg-surface-2 p-2 text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary'

function errorText(err: unknown, fallback: string): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

export function Users() {
  const currentUser = useAuthStore((s) => s.user)
  const queryClient = useQueryClient()
  const [message, setMessage] = useState<BannerMessage | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [resetFor, setResetFor] = useState<ManagedUser | null>(null)

  const { data: users = [], isLoading, error } = useQuery({
    queryKey: ['users'],
    queryFn: usersApi.list,
  })

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['users'] })

  const changeRole = async (user: ManagedUser, role: Role) => {
    try {
      await usersApi.update(user.id, { role })
      await refresh()
      setMessage({ type: 'success', text: `${user.email} is now ${role}.` })
    } catch (err) {
      setMessage({ type: 'error', text: errorText(err, 'Could not change the role.') })
    }
  }

  const toggleActive = async (user: ManagedUser) => {
    try {
      await usersApi.update(user.id, { is_active: !user.is_active })
      await refresh()
      setMessage({ type: 'success', text: `${user.email} ${user.is_active ? 'deactivated' : 'reactivated'}.` })
    } catch (err) {
      setMessage({ type: 'error', text: errorText(err, 'Could not change the account status.') })
    }
  }

  const deactivate = async (user: ManagedUser) => {
    if (!window.confirm(`Deactivate ${user.email}? They will not be able to sign in.`)) return
    try {
      await usersApi.deactivate(user.id)
      await refresh()
      setMessage({ type: 'success', text: `${user.email} deactivated.` })
    } catch (err) {
      setMessage({ type: 'error', text: errorText(err, 'Could not deactivate the account.') })
    }
  }

  if (error) {
    return (
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold">Users</h1>
        <NotificationBanner
          message={{ type: 'error', text: errorText(error, 'Only admins can manage users.') }}
          onDismiss={() => undefined}
          autoHideMs={0}
        />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Users</h1>
          <p className="text-sm text-muted-foreground">
            Admins manage accounts. Viewers and clients read, analysts also make changes.
          </p>
        </div>
        <Button onClick={() => setShowCreate((v) => !v)}>
          {showCreate ? 'Close' : 'Add user'}
        </Button>
      </div>

      <NotificationBanner message={message} onDismiss={() => setMessage(null)} />

      {showCreate && (
        <CreateUserCard
          onCreated={async (email) => {
            setShowCreate(false)
            await refresh()
            setMessage({ type: 'success', text: `${email} created.` })
          }}
          onError={(text) => setMessage({ type: 'error', text })}
        />
      )}

      {resetFor && (
        <ResetPasswordCard
          user={resetFor}
          onDone={async () => {
            setMessage({ type: 'success', text: `Password reset for ${resetFor.email}.` })
            setResetFor(null)
          }}
          onCancel={() => setResetFor(null)}
          onError={(text) => setMessage({ type: 'error', text })}
        />
      )}

      <Card>
        <CardHeader>
          <CardTitle>Accounts</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Email</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>MFA</TableHead>
                  <TableHead>Last sign-in</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((user) => {
                  const isSelf = user.id === currentUser?.id
                  return (
                    <TableRow key={user.id}>
                      <TableCell>
                        {user.email}
                        {isSelf && <span className="ml-2 text-xs text-muted-foreground">(you)</span>}
                      </TableCell>
                      <TableCell>
                        <select
                          aria-label={`Role for ${user.email}`}
                          value={user.role}
                          disabled={isSelf}
                          onChange={(e) => changeRole(user, e.target.value as Role)}
                          className="rounded border border-border bg-surface-2 px-2 py-1 text-sm"
                        >
                          {ROLES.map((r) => (
                            <option key={r} value={r}>{r}</option>
                          ))}
                        </select>
                      </TableCell>
                      <TableCell>
                        <Badge variant={user.is_active ? 'default' : 'secondary'}>
                          {user.is_active ? 'Active' : 'Inactive'}
                        </Badge>
                      </TableCell>
                      <TableCell>{user.mfa_enabled ? 'On' : 'Off'}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {user.last_login_at ? new Date(user.last_login_at).toLocaleString() : 'Never'}
                      </TableCell>
                      <TableCell className="space-x-2">
                        <Button variant="ghost" size="sm" onClick={() => setResetFor(user)}>
                          Reset password
                        </Button>
                        <Button variant="ghost" size="sm" disabled={isSelf} onClick={() => toggleActive(user)}>
                          {user.is_active ? 'Deactivate' : 'Reactivate'}
                        </Button>
                        <Button variant="ghost" size="sm" disabled={isSelf} onClick={() => deactivate(user)}>
                          Remove
                        </Button>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function CreateUserCard({
  onCreated,
  onError,
}: {
  onCreated: (email: string) => Promise<void>
  onError: (text: string) => void
}) {
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<Role>('viewer')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const problem = validatePasswordLocally(password)
    if (problem) return onError(problem)
    setBusy(true)
    try {
      await usersApi.create({ email, password, full_name: name || undefined, role })
      setEmail('')
      setName('')
      setPassword('')
      await onCreated(email)
    } catch (err) {
      onError(errorText(err, 'Could not create the user.'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>New user</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="grid gap-3 md:grid-cols-5">
          <input aria-label="Email" type="email" required placeholder="name@company.com"
            value={email} onChange={(e) => setEmail(e.target.value)} className={INPUT} />
          <input aria-label="Full name" placeholder="Full name (optional)"
            value={name} onChange={(e) => setName(e.target.value)} className={INPUT} />
          <input aria-label="Initial password" type="password" required placeholder="Initial password"
            value={password} onChange={(e) => setPassword(e.target.value)} className={INPUT} />
          <select aria-label="Role" value={role} onChange={(e) => setRole(e.target.value as Role)} className={INPUT}>
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <Button type="submit" disabled={busy}>Create user</Button>
        </form>
      </CardContent>
    </Card>
  )
}

function ResetPasswordCard({
  user,
  onDone,
  onCancel,
  onError,
}: {
  user: ManagedUser
  onDone: () => Promise<void>
  onCancel: () => void
  onError: (text: string) => void
}) {
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const problem = validatePasswordLocally(password)
    if (problem) return onError(problem)
    setBusy(true)
    try {
      await usersApi.resetPassword(user.id, password)
      setPassword('')
      await onDone()
    } catch (err) {
      onError(errorText(err, 'Could not reset the password.'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Reset password for {user.email}</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="flex gap-3">
          <input aria-label="New password" type="password" required placeholder="New password"
            value={password} onChange={(e) => setPassword(e.target.value)} className={INPUT} />
          <Button type="submit" disabled={busy}>Set password</Button>
          <Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button>
        </form>
      </CardContent>
    </Card>
  )
}
