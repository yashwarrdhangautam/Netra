import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Play, Square } from 'lucide-react'
import { HuntProfile, bugBountyApi } from '@/api/bugbounty'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { StatusPill } from '@/components/bugbounty/StatusAtoms'
import { formatRelativeTime } from '@/utils/formatters'

export function BBHunts() {
  const client = useQueryClient()
  const [programId, setProgramId] = useState('')
  const [profile, setProfile] = useState<HuntProfile>('passive')
  const [agentic, setAgentic] = useState(false)
  const [dryRun, setDryRun] = useState(false)
  const [confirm, setConfirm] = useState('')
  const [selectedExplainId, setSelectedExplainId] = useState('')
  const programs = useQuery({ queryKey: ['bb-programs'], queryFn: bugBountyApi.programs })
  const hunts = useQuery({ queryKey: ['bb-hunts'], queryFn: () => bugBountyApi.hunts(), refetchInterval: 10000 })
  const explain = useQuery({
    queryKey: ['bb-hunt-explain', selectedExplainId],
    queryFn: () => bugBountyApi.explainHunt(selectedExplainId),
    enabled: Boolean(selectedExplainId),
  })
  const selectedProgram = programs.data?.find((program) => program.id === programId)
  const planPreview = useQuery({
    queryKey: ['bb-plan-preview', programId, selectedProgram?.handle],
    queryFn: () => bugBountyApi.previewPlan(programId, selectedProgram?.handle),
    enabled: Boolean(agentic && programId),
  })
  const createHunt = useMutation({
    mutationFn: () => bugBountyApi.createHunt(programId, profile, {
      active_confirmed: profile === 'active',
      agentic,
      dry_run: dryRun,
    }),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ['bb-hunts'] })
      setSelectedExplainId('')
    },
  })
  const cancelHunt = useMutation({
    mutationFn: bugBountyApi.cancelHunt,
    onSuccess: () => client.invalidateQueries({ queryKey: ['bb-hunts'] }),
  })
  const activeReady = profile === 'passive' || confirm === 'CONFIRM'

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Hunt Console</h1>
        <p className="text-sm text-muted-foreground">Launch passive or explicitly confirmed active hunts.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>New Hunt</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-3 md:grid-cols-[1fr_220px_auto]">
            <select value={programId} onChange={(event) => setProgramId(event.target.value)} className="rounded border border-border bg-surface-2 px-3 py-2 text-sm">
              <option value="">Select program</option>
              {programs.data?.map((program) => <option key={program.id} value={program.id}>{program.platform}/{program.handle}</option>)}
            </select>
            <select value={profile} onChange={(event) => setProfile(event.target.value as HuntProfile)} className="rounded border border-border bg-surface-2 px-3 py-2 text-sm">
              <option value="passive">Passive</option>
              <option value="active">Active</option>
            </select>
            <Button disabled={!programId || !activeReady || createHunt.isPending} onClick={() => createHunt.mutate()}>
              <Play className="mr-2 h-4 w-4" />
              Run
            </Button>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <label className="flex items-center gap-2 rounded border border-border bg-surface-2 px-3 py-2 text-sm">
              <input type="checkbox" checked={agentic} onChange={(event) => setAgentic(event.target.checked)} />
              Agentic planner and tool router
            </label>
            <label className="flex items-center gap-2 rounded border border-border bg-surface-2 px-3 py-2 text-sm">
              <input type="checkbox" checked={dryRun} onChange={(event) => setDryRun(event.target.checked)} disabled={!agentic} />
              Dry run / plan only
            </label>
          </div>
          {agentic ? (
            <div className="rounded border border-border bg-surface-2 p-3 text-sm">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="font-medium">Plan Preview</div>
                  <p className="text-muted-foreground">Graph-backed coordination for the currently selected program.</p>
                </div>
                <Button variant="outline" size="sm" onClick={() => planPreview.refetch()} disabled={!programId || planPreview.isFetching}>
                  Refresh
                </Button>
              </div>
              {planPreview.isLoading || planPreview.isFetching ? (
                <Skeleton className="mt-3 h-28 w-full" />
              ) : planPreview.data ? (
                <div className="mt-3 space-y-3">
                  <p className="text-muted-foreground">{String((planPreview.data.coordination.summary as string) || planPreview.data.rationale || '')}</p>
                  {Array.isArray(planPreview.data.coordination.focus_areas) && planPreview.data.coordination.focus_areas.length ? (
                    <div className="flex flex-wrap gap-2">
                      {(planPreview.data.coordination.focus_areas as string[]).map((item) => (
                        <span key={item} className="rounded border border-border px-2 py-1 text-xs">{item}</span>
                      ))}
                    </div>
                  ) : null}
                  {Array.isArray(planPreview.data.coordination.retrieval_hits) && planPreview.data.coordination.retrieval_hits.length ? (
                    <div className="space-y-2">
                      {(planPreview.data.coordination.retrieval_hits as Array<Record<string, unknown>>).slice(0, 3).map((hit, index) => (
                        <div key={`${String(hit.title || 'hit')}-${index}`} className="rounded border border-border bg-background p-3">
                          <div className="font-medium">{String(hit.title || 'hit')}</div>
                          <div className="text-xs text-muted-foreground">{String(hit.source || '')}</div>
                          <p className="mt-2 text-muted-foreground">{String(hit.snippet || '')}</p>
                        </div>
                      ))}
                    </div>
                  ) : null}
                  {planPreview.data.steps?.length ? (
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead className="text-left text-xs uppercase text-muted-foreground">
                          <tr>
                            <th className="py-2">Class</th>
                            <th>Tool</th>
                            <th>Target</th>
                          </tr>
                        </thead>
                        <tbody>
                          {planPreview.data.steps.slice(0, 5).map((step, index) => (
                            <tr key={`${String(step.vuln_class || 'step')}-${index}`} className="border-t border-border">
                              <td className="py-2">{String(step.vuln_class || '')}</td>
                              <td>{String(step.suggested_tool || '')}</td>
                              <td className="font-mono text-xs">{String(step.target || '')}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : null}
                </div>
              ) : (
                <p className="mt-3 text-muted-foreground">Select a program to preview its agentic plan.</p>
              )}
            </div>
          ) : null}
          {profile === 'active' ? (
            <div className="rounded border border-amber-700 bg-amber-950/30 p-3 text-sm text-amber-100">
              Active testing may send ffuf or nuclei traffic. Type <span className="font-mono">CONFIRM</span> to enable the Run button for {selectedProgram?.handle || 'this program'}.
              <input value={confirm} onChange={(event) => setConfirm(event.target.value)} className="mt-2 w-full rounded border border-border bg-surface-2 px-3 py-2 font-mono text-sm text-foreground" />
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Hunts</CardTitle>
        </CardHeader>
        <CardContent>
          {hunts.isLoading ? (
            <Skeleton className="h-56 w-full" />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="py-2">Name</th>
                    <th>Status</th>
                    <th>Profile</th>
                    <th>Mode</th>
                    <th>Assets</th>
                    <th>Findings</th>
                    <th>Blocks</th>
                    <th>Created</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {hunts.data?.map((hunt) => (
                    <tr key={hunt.id} className="border-t border-border">
                      <td className="py-2">{hunt.name}</td>
                      <td><StatusPill>{hunt.status}</StatusPill></td>
                      <td>{hunt.profile}</td>
                      <td>{hunt.mode}{hunt.dry_run ? ' / dry' : ''}</td>
                      <td className="font-mono tabular-nums">{hunt.assets_discovered}</td>
                      <td className="font-mono tabular-nums">{hunt.findings_count}</td>
                      <td className={hunt.blocked_count ? 'font-mono text-red-400' : 'font-mono text-green-400'}>{hunt.blocked_count}</td>
                      <td className="text-muted-foreground">{formatRelativeTime(hunt.created_at)}</td>
                      <td className="text-right">
                        {hunt.mode === 'agentic' ? (
                          <Button size="sm" variant="ghost" onClick={() => setSelectedExplainId(hunt.id)}>
                            Explain
                          </Button>
                        ) : null}
                        {hunt.status === 'running' || hunt.status === 'pending' ? (
                          <Button size="sm" variant="outline" onClick={() => cancelHunt.mutate(hunt.id)}>
                            <Square className="mr-2 h-4 w-4" />
                            Cancel
                          </Button>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {selectedExplainId ? (
        <Card>
          <CardHeader>
            <CardTitle>Agentic Trace</CardTitle>
          </CardHeader>
          <CardContent>
            {explain.isLoading ? (
              <Skeleton className="h-40 w-full" />
            ) : (
              <div className="space-y-3">
                {explain.data?.summary ? (
                  <div className="rounded border border-border bg-surface-2 p-3 text-sm">
                    <div className="font-medium">Coordination Summary</div>
                    <p className="mt-2 text-muted-foreground">{explain.data.summary}</p>
                    {explain.data.focus_areas.length ? (
                      <div className="mt-3">
                        <div className="text-xs uppercase text-muted-foreground">Focus</div>
                        <div className="mt-1 flex flex-wrap gap-2">
                          {explain.data.focus_areas.map((item) => (
                            <span key={item} className="rounded border border-border px-2 py-1 text-xs">{item}</span>
                          ))}
                        </div>
                      </div>
                    ) : null}
                    {explain.data.recommended_tools.length ? (
                      <div className="mt-3">
                        <div className="text-xs uppercase text-muted-foreground">Suggested tools</div>
                        <div className="mt-1 flex flex-wrap gap-2">
                          {explain.data.recommended_tools.map((item) => (
                            <span key={item} className="rounded border border-border px-2 py-1 text-xs">{item}</span>
                          ))}
                        </div>
                      </div>
                    ) : null}
                  </div>
                ) : null}
                {explain.data?.retrieval_hits?.length ? (
                  <div className="rounded border border-border bg-surface-2 p-3 text-sm">
                    <div className="font-medium">Graph / Knowledge Hits</div>
                    <div className="mt-3 space-y-2">
                      {explain.data.retrieval_hits.map((hit, index) => (
                        <div key={`${String(hit.title || 'hit')}-${index}`} className="rounded border border-border bg-background p-3">
                          <div className="font-medium">{String(hit.title || 'hit')}</div>
                          <div className="text-xs text-muted-foreground">{String(hit.source || '')}</div>
                          <p className="mt-2 text-muted-foreground">{String(hit.snippet || '')}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
                {explain.data?.attack_paths?.length ? (
                  <div className="rounded border border-border bg-surface-2 p-3 text-sm">
                    <div className="font-medium">Attack Paths</div>
                    <div className="mt-3 space-y-2">
                      {explain.data.attack_paths.map((path, index) => (
                        <div key={`${String(path.name || 'path')}-${index}`} className="rounded border border-border bg-background p-3">
                          <div className="font-medium">{String(path.name || 'path')}</div>
                          <div className="mt-1 font-mono text-xs text-muted-foreground">
                            {Array.isArray(path.steps) ? path.steps.map((item) => String(item)).join(' -> ') : String(path.steps || '')}
                          </div>
                          <p className="mt-2 text-muted-foreground">{String(path.narrative || '')}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
                {(explain.data?.steps || []).map((step) => (
                  <div key={`${step.step_n}-${step.tool_chosen}`} className="rounded border border-border bg-surface-2 p-3 text-sm">
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-xs text-muted-foreground">#{String(step.step_n)}</span>
                      <StatusPill>{String(step.status)}</StatusPill>
                      <span className="font-medium">{String(step.tool_chosen || 'tool')}</span>
                    </div>
                    <p className="mt-2 text-muted-foreground">{String(step.decision_rationale || '')}</p>
                    <pre className="mt-3 overflow-auto rounded border border-border bg-background p-3 font-mono text-xs text-muted-foreground">
                      {JSON.stringify(step.observations_out || {}, null, 2)}
                    </pre>
                  </div>
                ))}
                {!explain.data?.steps?.length ? <p className="text-sm text-muted-foreground">No agentic trace recorded for this hunt yet.</p> : null}
              </div>
            )}
          </CardContent>
        </Card>
      ) : null}
    </div>
  )
}
