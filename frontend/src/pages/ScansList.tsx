import { useEffect, useState } from 'react'
import { Link } from '@tanstack/react-router'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeftRight, Plus, Trash2 } from 'lucide-react'
import { scansApi, type CreateScanPayload } from '@/api/scans'
import { targetsApi } from '@/api/targets'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table'
import { NotificationBanner, type BannerMessage } from '@/components/shared/NotificationBanner'
import { useAuthStore } from '@/stores/authStore'
import { cn, formatRelativeTime } from '@/utils/formatters'
import { consumePendingNewScan } from '@/utils/newScan'
import type { ScanList } from '@/types'

const PROFILES = [
  'quick',
  'standard',
  'deep',
  'api_only',
  'cloud',
  'mobile',
  'container',
  'ai_llm',
  'custom',
] as const

const INPUT = cn(
  'w-full rounded-md border border-border bg-surface-2 px-3 py-2 text-sm text-foreground',
  'focus:outline-none focus:ring-2 focus:ring-accent'
)

function errorText(err: unknown, fallback: string): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail) && detail.length > 0 && (detail[0] as { msg?: string }).msg) {
    return (detail[0] as { msg: string }).msg
  }
  return fallback
}

export function ScansList() {
  const queryClient = useQueryClient()
  const canEdit = useAuthStore((s) => s.canEdit)()
  const [creating, setCreating] = useState(false)
  const [message, setMessage] = useState<BannerMessage | null>(null)
  const [form, setForm] = useState({ name: '', targetId: '', profile: 'standard' as CreateScanPayload['profile'] })

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list({}),
  })

  const { data: targets } = useQuery({
    queryKey: ['targets-for-scans'],
    queryFn: () => targetsApi.list(),
    enabled: creating,
  })

  // The header "New scan" button dispatches this event.
  useEffect(() => {
    if (!canEdit) return
    // Opened from another page: the header navigated here and left a one-shot flag.
    if (consumePendingNewScan()) setCreating(true)
    const open = () => setCreating(true)
    window.addEventListener('netra:new-scan', open)
    return () => window.removeEventListener('netra:new-scan', open)
  }, [canEdit])

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['scans'] })

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await scansApi.create({ name: form.name, target_id: form.targetId, profile: form.profile })
      setCreating(false)
      setForm({ name: '', targetId: '', profile: 'standard' })
      setMessage({ type: 'success', text: 'Scan queued. It runs on the worker; watch the status here.' })
      await refresh()
    } catch (err) {
      setMessage({ type: 'error', text: errorText(err, 'Could not start the scan.') })
    }
  }

  const remove = async (scan: ScanList) => {
    if (!window.confirm(`Delete scan “${scan.name}” and its findings? This cannot be undone.`)) return
    try {
      await scansApi.delete(scan.id)
      setMessage({ type: 'success', text: 'Scan deleted.' })
      await refresh()
    } catch (err) {
      setMessage({ type: 'error', text: errorText(err, 'Could not delete the scan.') })
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Scans</h1>
        <div className="flex gap-2">
          <Link to="/scans/compare">
            <Button variant="outline" size="sm">
              <ArrowLeftRight className="mr-2 h-4 w-4" />
              Compare
            </Button>
          </Link>
          {canEdit && (
            <Button size="sm" onClick={() => setCreating((v) => !v)}>
              <Plus className="mr-2 h-4 w-4" />
              {creating ? 'Close' : 'New scan'}
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={() => refetch()}>Refresh</Button>
        </div>
      </div>

      <NotificationBanner message={message} onDismiss={() => setMessage(null)} />

      {creating && canEdit && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">New scan</CardTitle>
          </CardHeader>
          <CardContent>
            {(targets?.items.length ?? 0) === 0 ? (
              <p className="text-sm text-muted-foreground">
                Add a target first. Scans run against targets.{' '}
                <Link to="/targets" className="text-accent underline">Go to Targets</Link>
              </p>
            ) : (
              <form onSubmit={submit} className="grid gap-3 md:grid-cols-4">
                <label className="space-y-1 text-sm">
                  <span>Name</span>
                  <input className={INPUT} required value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })} />
                </label>
                <label className="space-y-1 text-sm">
                  <span>Target</span>
                  <select className={INPUT} required value={form.targetId}
                    onChange={(e) => setForm({ ...form, targetId: e.target.value })}>
                    <option value="">Choose…</option>
                    {targets?.items.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                  </select>
                </label>
                <label className="space-y-1 text-sm">
                  <span>Profile</span>
                  <select className={INPUT} value={form.profile}
                    onChange={(e) => setForm({ ...form, profile: e.target.value as CreateScanPayload['profile'] })}>
                    {PROFILES.map((p) => <option key={p} value={p}>{p}</option>)}
                  </select>
                </label>
                <div className="flex items-end">
                  <Button type="submit" disabled={!form.targetId || !form.name.trim()}>Start scan</Button>
                </div>
              </form>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>All scans</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-muted-foreground">Loading…</div>
          ) : (data?.items.length ?? 0) === 0 ? (
            <p className="text-sm text-muted-foreground">
              No scans yet. {canEdit ? 'Use “New scan” to start one.' : ''}
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Profile</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data?.items.map((scan: ScanList) => (
                  <TableRow key={scan.id}>
                    <TableCell className="font-medium">{scan.name}</TableCell>
                    <TableCell>
                      <Badge variant={scan.status === 'completed' ? 'default' : 'secondary'}>
                        {scan.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{scan.profile}</TableCell>
                    <TableCell className="text-muted-foreground">{formatRelativeTime(scan.created_at)}</TableCell>
                    <TableCell className="space-x-1">
                      <Link to="/scans/$scanId" params={{ scanId: scan.id }}>
                        <Button variant="ghost" size="sm">View</Button>
                      </Link>
                      {canEdit && (
                        <Button variant="ghost" size="sm" aria-label={`Delete ${scan.name}`}
                          onClick={() => remove(scan)}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
