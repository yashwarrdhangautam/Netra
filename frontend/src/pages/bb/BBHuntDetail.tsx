import { useCallback, useRef } from 'react'
import { Link, useParams } from '@tanstack/react-router'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import { bugBountyApi } from '@/api/bugbounty'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { PhaseTimeline } from '@/components/scans/PhaseTimeline'
import { formatRelativeTime } from '@/utils/formatters'
import { useAuthStore } from '@/stores/authStore'
import { useWebSocket } from '@/hooks/useWebSocket'

interface HuntDetail {
  id: string
  status: string
  profile: string
  mode: string
  dry_run?: boolean
  assets_discovered: number
  findings_count: number
  blocked_count: number
  created_at: string
}

interface PhaseRow {
  phase_type: string
  status: string
  progress: number
  findings_count: number
  started_at?: string | null
  completed_at?: string | null
}

const ACTIVE = new Set(['pending', 'running', 'queued'])

export function BBHuntDetail() {
  const { huntId } = useParams({ strict: false }) as { huntId: string }
  const queryClient = useQueryClient()

  const token = useAuthStore((s) => s.token)
  // Read by the queries below, and written after the socket hook runs. A ref avoids a cycle.
  const socketLive = useRef(false)
  const fallbackPoll = (status?: string) =>
    status && ACTIVE.has(status) && !socketLive.current ? 2000 : false

  const hunt = useQuery({
    queryKey: ['bb-hunt', huntId],
    queryFn: async () => (await apiClient.get<HuntDetail>(`/api/v1/bb/hunts/${huntId}`)).data,
    refetchInterval: (q) => fallbackPoll((q.state.data as HuntDetail | undefined)?.status),
  })

  const phases = useQuery({
    queryKey: ['bb-hunt-phases', huntId],
    queryFn: async () => (await apiClient.get<PhaseRow[]>(`/api/v1/scans/${huntId}/phases`)).data,
    enabled: !!huntId,
    refetchInterval: () => fallbackPoll(hunt.data?.status),
  })

  // The server pushes the hunt's status and phases while it runs, and closes when it ends.
  // Polling is only a fallback for when the socket is down.
  const isActive = hunt.data ? ACTIVE.has(hunt.data.status) : true
  const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws'
  const wsUrl = huntId && token
    ? `${scheme}://${window.location.host}/ws/scans/${huntId}?token=${encodeURIComponent(token)}`
    : ''
  const onSnapshot = useCallback(
    (message: unknown) => {
      const snap = message as { phases?: PhaseRow[]; status?: string; error?: string }
      if (snap.error || !snap.phases) return
      queryClient.setQueryData(['bb-hunt-phases', huntId], snap.phases)
      queryClient.invalidateQueries({ queryKey: ['bb-hunt', huntId] })
    },
    [queryClient, huntId],
  )
  const { isConnected } = useWebSocket({
    url: wsUrl,
    onMessage: onSnapshot,
    enabled: Boolean(wsUrl) && isActive,
  })
  socketLive.current = isConnected

  const cancel = useMutation({
    mutationFn: () => bugBountyApi.cancelHunt(huntId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['bb-hunt', huntId] }),
  })

  if (hunt.isLoading) return <p className="text-sm text-muted-foreground">Loading hunt…</p>
  if (hunt.error || !hunt.data) {
    return (
      <div className="space-y-3">
        <Link to="/bb/hunts" className="text-sm text-accent underline">Back to hunts</Link>
        <p className="text-sm text-red-400">This hunt could not be loaded.</p>
      </div>
    )
  }

  const h = hunt.data
  const running = ACTIVE.has(h.status)
  const clean = h.blocked_count === 0

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Link to="/bb/hunts" className="text-sm text-accent underline">Back to hunts</Link>
          <h1 className="mt-1 text-2xl font-semibold text-foreground">Hunt {h.id.slice(0, 8)}</h1>
          <p className="text-sm text-muted-foreground">
            {h.profile} · {h.mode}{h.dry_run ? ' · dry run' : ''} · started {formatRelativeTime(h.created_at)}
          </p>
        </div>
        {running && (
          <Button variant="outline" onClick={() => cancel.mutate()} disabled={cancel.isPending}>
            {cancel.isPending ? 'Cancelling…' : 'Cancel hunt'}
          </Button>
        )}
      </div>

      <div
        role="status"
        className={
          clean
            ? 'rounded-md border border-green-700 bg-green-900/20 px-4 py-3 text-sm text-green-300'
            : 'rounded-md border border-red-700 bg-red-900/20 px-4 py-3 text-sm text-red-300'
        }
      >
        {clean
          ? 'Zero out-of-scope traffic so far.'
          : `${h.blocked_count} out-of-scope attempt(s) blocked. See the BB audit log.`}
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Stat label="Status" value={h.status} />
        <Stat label="Assets discovered" value={h.assets_discovered} />
        <Stat label="Findings" value={h.findings_count} />
        <Stat label="Blocked" value={h.blocked_count} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Phases</CardTitle>
        </CardHeader>
        <CardContent>
          {phases.isLoading ? (
            <p className="text-sm text-muted-foreground">Loading phases…</p>
          ) : (phases.data?.length ?? 0) === 0 ? (
            <p className="text-sm text-muted-foreground">
              No phases yet. The worker starts them; it must be running.
            </p>
          ) : (
            <PhaseTimeline phases={phases.data ?? []} />
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-md border border-border p-4">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 font-mono text-xl tabular-nums text-foreground">{value}</div>
    </div>
  )
}
