import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { targetsApi } from '@/api/targets'
import { schedulesApi, type ScheduleItem } from '@/api/platform'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table'
import { NotificationBanner, type BannerMessage } from '@/components/shared/NotificationBanner'
import { useAuthStore } from '@/stores/authStore'
import { cn } from '@/utils/formatters'

const PROFILES = ['quick', 'standard', 'deep', 'api_only', 'cloud', 'mobile', 'container', 'ai_llm']
const INPUT = cn(
  'w-full rounded-md border border-border bg-surface-2 px-3 py-2 text-sm text-foreground',
  'focus:outline-none focus:ring-2 focus:ring-accent'
)

type Kind = 'interval' | 'cron' | 'once'

function errorText(err: unknown, fallback: string): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0] as { msg?: string }
    if (first?.msg) return first.msg
  }
  return fallback
}

export function Schedules() {
  const queryClient = useQueryClient()
  const canEdit = useAuthStore((s) => s.canEdit)()
  const [message, setMessage] = useState<BannerMessage | null>(null)
  const [kind, setKind] = useState<Kind>('interval')
  const [form, setForm] = useState({
    name: '',
    targetId: '',
    profile: 'standard',
    everyHours: '24',
    cron: '0 2 * * *',
    runAt: '',
  })

  const { data: schedules = [], isLoading } = useQuery({
    queryKey: ['schedules'],
    queryFn: schedulesApi.list,
    refetchInterval: 30000,
  })

  const { data: targets } = useQuery({
    queryKey: ['targets-for-schedules'],
    queryFn: () => targetsApi.list(),
  })

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['schedules'] })

  const run = async (action: () => Promise<void>, ok: string, fail: string) => {
    try {
      await action()
      setMessage({ type: 'success', text: ok })
      await refresh()
    } catch (err) {
      setMessage({ type: 'error', text: errorText(err, fail) })
    }
  }

  const create = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!form.targetId) return setMessage({ type: 'error', text: 'Choose a target.' })
    try {
      if (kind === 'interval') {
        await schedulesApi.createInterval({
          name: form.name,
          target_id: form.targetId,
          interval_seconds: Math.round(Number(form.everyHours) * 3600),
          profile: form.profile,
        })
      } else if (kind === 'cron') {
        await schedulesApi.createCron({
          name: form.name,
          target_id: form.targetId,
          cron_expression: form.cron.trim(),
          profile: form.profile,
        })
      } else {
        if (!form.runAt) return setMessage({ type: 'error', text: 'Choose a date and time.' })
        await schedulesApi.createOnce({
          name: form.name,
          target_id: form.targetId,
          scheduled_at: new Date(form.runAt).toISOString(),
          profile: form.profile,
        })
      }
      setForm({ ...form, name: '' })
      setMessage({ type: 'success', text: 'Schedule created.' })
      await refresh()
    } catch (err) {
      setMessage({ type: 'error', text: errorText(err, 'Could not create the schedule.') })
    }
  }

  const when = (item: ScheduleItem) => {
    const next = item.next_run_at ? new Date(item.next_run_at).toLocaleString() : 'not scheduled'
    return item.schedule_type === 'once' && !item.is_active ? 'done' : next
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Schedules</h1>
        <p className="text-sm text-muted-foreground">
          Recurring or one-time scans. Scheduled scans run on the worker, so the worker must be running.
        </p>
      </div>

      <NotificationBanner message={message} onDismiss={() => setMessage(null)} />

      {canEdit && (
        <Card>
          <CardHeader>
            <CardTitle>New schedule</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={create} className="grid gap-3 md:grid-cols-3">
              <label className="space-y-1 text-sm">
                <span>Name</span>
                <input className={INPUT} required value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </label>
              <label className="space-y-1 text-sm">
                <span>Target</span>
                <select className={INPUT} value={form.targetId}
                  onChange={(e) => setForm({ ...form, targetId: e.target.value })}>
                  <option value="">Choose…</option>
                  {targets?.items.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                </select>
              </label>
              <label className="space-y-1 text-sm">
                <span>Profile</span>
                <select className={INPUT} value={form.profile}
                  onChange={(e) => setForm({ ...form, profile: e.target.value })}>
                  {PROFILES.map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
              </label>
              <label className="space-y-1 text-sm">
                <span>Type</span>
                <select className={INPUT} value={kind} onChange={(e) => setKind(e.target.value as Kind)}>
                  <option value="interval">Every N hours</option>
                  <option value="cron">Cron expression</option>
                  <option value="once">Once</option>
                </select>
              </label>
              {kind === 'interval' && (
                <label className="space-y-1 text-sm">
                  <span>Hours between runs (minimum 0.084 = 5 min)</span>
                  <input className={INPUT} type="number" min="0.084" step="0.5" value={form.everyHours}
                    onChange={(e) => setForm({ ...form, everyHours: e.target.value })} />
                </label>
              )}
              {kind === 'cron' && (
                <label className="space-y-1 text-sm">
                  <span>Cron (minute hour day month weekday)</span>
                  <input className={INPUT} value={form.cron}
                    onChange={(e) => setForm({ ...form, cron: e.target.value })} />
                </label>
              )}
              {kind === 'once' && (
                <label className="space-y-1 text-sm">
                  <span>Run at</span>
                  <input className={INPUT} type="datetime-local" value={form.runAt}
                    onChange={(e) => setForm({ ...form, runAt: e.target.value })} />
                </label>
              )}
              <div className="flex items-end md:col-span-3">
                <Button type="submit">Create schedule</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>All schedules</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : schedules.length === 0 ? (
            <p className="text-sm text-muted-foreground">No schedules yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Profile</TableHead>
                  <TableHead>Next run</TableHead>
                  <TableHead>Runs</TableHead>
                  <TableHead>Status</TableHead>
                  {canEdit && <TableHead>Actions</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {schedules.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell className="font-medium">{item.name}</TableCell>
                    <TableCell>{item.schedule_type}</TableCell>
                    <TableCell>{item.profile}</TableCell>
                    <TableCell className="text-xs">{when(item)}</TableCell>
                    <TableCell>{item.total_runs}</TableCell>
                    <TableCell>
                      <Badge variant={item.is_active ? 'default' : 'secondary'}>
                        {item.is_active ? 'Active' : 'Paused'}
                      </Badge>
                    </TableCell>
                    {canEdit && (
                      <TableCell className="space-x-1">
                        <Button variant="ghost" size="sm"
                          onClick={() => run(() => schedulesApi.runNow(item.id), 'Run queued.', 'Could not start a run.')}>
                          Run now
                        </Button>
                        {item.is_active ? (
                          <Button variant="ghost" size="sm"
                            onClick={() => run(() => schedulesApi.deactivate(item.id), 'Paused.', 'Could not pause.')}>
                            Pause
                          </Button>
                        ) : (
                          <Button variant="ghost" size="sm"
                            onClick={() => run(() => schedulesApi.activate(item.id), 'Resumed.', 'Could not resume.')}>
                            Resume
                          </Button>
                        )}
                        <Button variant="ghost" size="sm"
                          onClick={() => run(() => schedulesApi.remove(item.id), 'Deleted.', 'Could not delete.')}>
                          Delete
                        </Button>
                      </TableCell>
                    )}
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
