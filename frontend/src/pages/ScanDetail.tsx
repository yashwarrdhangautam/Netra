import { useState } from 'react'
import { useParams } from '@tanstack/react-router'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { scansApi } from '@/api/scans'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Skeleton } from '@/components/ui/Skeleton'

interface ScanPhaseRow {
  id: string
  phase_type: string
  status: string
  findings_count: number
  started_at: string | null
  completed_at: string | null
  error_message?: string | null
}

const ACTIVE_STATES = new Set(['pending', 'running'])

function duration(start: string | null, end: string | null): string {
  if (!start) return ''
  const ms = (end ? new Date(end) : new Date()).getTime() - new Date(start).getTime()
  if (!Number.isFinite(ms) || ms < 0) return ''
  const minutes = Math.floor(ms / 60000)
  if (minutes < 1) return '<1 min'
  const hours = Math.floor(minutes / 60)
  return hours ? `${hours} h ${minutes % 60} min` : `${minutes} min`
}

export function ScanDetail() {
  const { scanId } = useParams({ strict: false })
  const queryClient = useQueryClient()
  const [confirmStop, setConfirmStop] = useState<'cancelled' | 'paused' | null>(null)

  const { data: scan, isLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId as string),
    enabled: !!scanId,
    // A running scan can take hours; keep the page current without a manual refresh.
    refetchInterval: (query) =>
      ACTIVE_STATES.has(String(query.state.data?.status ?? '')) ? 5000 : false,
  })

  const active = ACTIVE_STATES.has(String(scan?.status ?? ''))

  const { data: phases } = useQuery({
    queryKey: ['scan-phases', scanId],
    queryFn: () => scansApi.getPhases(scanId as string) as Promise<ScanPhaseRow[]>,
    enabled: !!scanId,
    refetchInterval: active ? 5000 : false,
  })

  const stop = useMutation({
    mutationFn: (status: 'cancelled' | 'paused') =>
      scansApi.update(scanId as string, { status }),
    onSuccess: () => {
      setConfirmStop(null)
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] })
      queryClient.invalidateQueries({ queryKey: ['scan-phases', scanId] })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })

  if (isLoading) {
    return <Skeleton className="h-96 w-full" />
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-bold">{scan?.name}</h1>
        <div className="flex items-center gap-2">
          <Badge variant={scan?.status === 'completed' ? 'default' : 'secondary'}>
            {scan?.status}
          </Badge>
          {active && !confirmStop && (
            <>
              <Button size="sm" variant="secondary" onClick={() => setConfirmStop('paused')}>
                Pause
              </Button>
              <Button size="sm" variant="destructive" onClick={() => setConfirmStop('cancelled')}>
                Cancel scan
              </Button>
            </>
          )}
          {active && confirmStop && (
            <>
              <span className="text-sm text-muted-foreground">
                {confirmStop === 'cancelled'
                  ? 'Cancel this scan? Running tools are stopped within a few seconds.'
                  : 'Pause this scan? It can be resumed later.'}
              </span>
              <Button
                size="sm"
                variant={confirmStop === 'cancelled' ? 'destructive' : 'secondary'}
                disabled={stop.isPending}
                onClick={() => stop.mutate(confirmStop)}
              >
                {confirmStop === 'cancelled' ? 'Yes, cancel' : 'Yes, pause'}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setConfirmStop(null)}>
                Keep running
              </Button>
            </>
          )}
        </div>
      </div>
      {stop.isError && (
        <p className="text-sm text-red-400">The scan could not be stopped. Refresh and try again.</p>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{scan?.outcome === 'complete' ? 'Complete coverage' : 'Incomplete coverage'}</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-3 text-sm text-muted-foreground">Coverage records which required tools completed. Zero findings do not establish that a target is secure.</p>
          {!scan?.coverage?.length && <p>Coverage evidence is unavailable for this scan.</p>}
          <ul className="space-y-2">
            {scan?.coverage?.map((run, index) => (
              <li key={`${run.phase}-${run.tool}-${index}`} className="text-sm">
                <span className="font-medium">{run.tool}</span> ({run.phase}) — {run.state}
                {run.required ? ' · required' : ' · optional'}
                {run.reason_code && <span> · {run.reason_code}</span>}
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Phases</CardTitle>
        </CardHeader>
        <CardContent>
          {!phases?.length && (
            <p className="text-sm text-muted-foreground">
              {active ? 'The first phase is running. Each phase appears here when it finishes.' : 'No phase records.'}
            </p>
          )}
          <ul className="space-y-2">
            {phases?.map((phase) => (
              <li key={phase.id} className="text-sm">
                <span className="font-medium">{phase.phase_type}</span> — {phase.status}
                {phase.started_at && <span> · {duration(phase.started_at, phase.completed_at)}</span>}
                <span> · {phase.findings_count} findings</span>
                {phase.error_message && (
                  <span className="block break-words text-muted-foreground">{phase.error_message}</span>
                )}
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Profile</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-lg font-medium">{scan?.profile}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Started</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-lg font-medium">{scan?.started_at ? new Date(scan.started_at).toLocaleString() : 'N/A'}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Completed</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-lg font-medium">{scan?.completed_at ? new Date(scan.completed_at).toLocaleString() : 'N/A'}</p>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
