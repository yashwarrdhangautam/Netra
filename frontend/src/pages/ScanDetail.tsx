import { useState } from 'react'
import { Link, useParams } from '@tanstack/react-router'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { scansApi } from '@/api/scans'
import { findingsApi } from '@/api/findings'
import { reportsApi, reportFilename, type ReportType } from '@/api/reports'
import { reportFilesApi } from '@/api/platform'
import apiClient from '@/api/client'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Skeleton } from '@/components/ui/Skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table'
import { FindingsTable } from '@/components/findings/FindingsTable'
import { cn } from '@/utils/formatters'
import type { FindingSearch } from '@/utils/findingSearch'

interface ToolRun {
  tool: string
  target: string
  state: string
  status: string
  reason_code?: string | null
  reason?: string | null
  error?: string | null
  raw_results?: number | null
  detail?: string | null
  progress?: { requests?: number; total?: number; percent?: number; errors?: number } | null
  artifacts?: { kind: string; name: string; bytes?: number }[]
}

interface ScanPhaseRow {
  id: string
  phase_type: string
  status: string
  outcome?: string | null
  findings_count: number
  stored_findings?: number | null
  started_at: string | null
  completed_at: string | null
  error_message?: string | null
  runs?: ToolRun[]
}

interface ReportRow {
  id: string
  scan_id: string
  report_type: string
  status: string
  file_path?: string | null
  file_size?: number | null
  error_message?: string | null
  created_at: string
}

interface AssetHost {
  url: string
  hostname?: string
  status_code?: number
  title?: string
  tech?: string[]
  protections?: string[]
}

interface Assets {
  target: string | null
  passive_zone?: string | null
  passive_names_observed?: number | null
  subdomains_in_scope: string[]
  live_hosts: string[]
  hosts: AssetHost[]
  authorization: Record<string, unknown>
}

interface OwaspRow {
  id: string
  name: string
  state: string
  tools: string[]
  checks: string
  findings: number
  limitations: string
}

const ACTIVE_STATES = new Set(['pending', 'running'])
const TABS = ['Overview', 'Findings', 'Recon & assets', 'Tool execution', 'Coverage & limitations', 'Reports'] as const
type Tab = (typeof TABS)[number]

const PHASE_LABELS: Record<string, string> = {
  scope: 'Scope and passive discovery',
  recon_discovery: 'Reconnaissance',
  vuln_scan: 'Vulnerability scanning',
  pentest: 'Active testing',
  ai_analysis: 'AI analysis',
  reporting: 'Reporting',
}

// Outcome colours: only a full completion is green; warnings and partial runs never are.
const STATUS_STYLE: Record<string, string> = {
  completed: 'bg-green-500/20 text-green-300',
  completed_with_warnings: 'bg-amber-500/20 text-amber-300',
  skipped: 'bg-gray-500/20 text-gray-300',
  timed_out: 'bg-orange-500/20 text-orange-300',
  failed: 'bg-red-500/20 text-red-300',
  failed_interrupted: 'bg-red-500/20 text-red-300',
  not_configured: 'bg-gray-500/20 text-gray-300',
  running: 'bg-blue-500/20 text-blue-300',
  pending: 'bg-blue-500/20 text-blue-300',
  tested: 'bg-green-500/20 text-green-300',
  partially_tested: 'bg-amber-500/20 text-amber-300',
  not_tested: 'bg-gray-500/20 text-gray-300',
  requires_credentials: 'bg-purple-500/20 text-purple-300',
  requires_manual_review: 'bg-purple-500/20 text-purple-300',
}

const REPORT_OPTIONS: { type: ReportType; label: string; hint: string }[] = [
  { type: 'assessment_pdf', label: 'Assessment PDF', hint: 'Summary, scope, methodology, tool execution, coverage, findings, limitations' },
  { type: 'assessment_json', label: 'JSON', hint: 'Structured report data' },
  { type: 'findings_csv', label: 'CSV', hint: 'Findings export' },
  { type: 'sarif', label: 'SARIF', hint: 'For code-scanning dashboards' },
]

function StatusPill({ value }: { value: string }) {
  return (
    <span className={cn('inline-block rounded px-2 py-0.5 text-xs font-medium', STATUS_STYLE[value] ?? 'bg-surface-2')}>
      {value.replace(/_/g, ' ')}
    </span>
  )
}

function duration(start: string | null, end: string | null): string {
  if (!start) return ''
  const ms = (end ? new Date(end) : new Date()).getTime() - new Date(start).getTime()
  if (!Number.isFinite(ms) || ms < 0) return ''
  const minutes = Math.floor(ms / 60000)
  if (minutes < 1) return '<1 min'
  const hours = Math.floor(minutes / 60)
  return hours ? `${hours} h ${minutes % 60} min` : `${minutes} min`
}

function errorText(err: unknown, fallback: string): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

export function ScanDetail() {
  const { scanId } = useParams({ strict: false }) as { scanId?: string }
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<Tab>('Overview')
  const [confirmStop, setConfirmStop] = useState<'cancelled' | 'paused' | null>(null)
  const [findingFilters, setFindingFilters] = useState<FindingSearch>({ scan_id: scanId })
  const [reportMessage, setReportMessage] = useState<string | null>(null)

  const { data: scan, isLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId as string),
    enabled: !!scanId,
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
  const { data: summary } = useQuery({
    queryKey: ['findings-summary', scanId],
    queryFn: () => findingsApi.summary(scanId as string),
    enabled: !!scanId,
    refetchInterval: active ? 15000 : false,
  })
  const { data: assets } = useQuery({
    queryKey: ['scan-assets', scanId],
    queryFn: async () => (await apiClient.get<Assets>(`/api/v1/scans/${scanId}/assets`)).data,
    enabled: !!scanId && tab === 'Recon & assets',
  })
  const { data: owasp } = useQuery({
    queryKey: ['scan-owasp', scanId],
    queryFn: async () => (await apiClient.get<OwaspRow[]>(`/api/v1/scans/${scanId}/owasp-coverage`)).data,
    enabled: !!scanId && tab === 'Coverage & limitations',
  })
  const { data: reports = [] } = useQuery({
    queryKey: ['scan-reports', scanId],
    queryFn: async () => (await reportsApi.listForScan(scanId as string)) as unknown as ReportRow[],
    enabled: !!scanId && tab === 'Reports',
    refetchInterval: (query) => {
      const rows = (query.state.data ?? []) as ReportRow[]
      return rows.some((r) => r.status === 'generating' || r.status === 'pending') ? 3000 : false
    },
  })

  const stop = useMutation({
    mutationFn: (status: 'cancelled' | 'paused') => scansApi.update(scanId as string, { status }),
    onSuccess: () => {
      setConfirmStop(null)
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] })
      queryClient.invalidateQueries({ queryKey: ['scan-phases', scanId] })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })

  const generate = useMutation({
    mutationFn: (type: ReportType) => reportsApi.generate(scanId as string, type),
    onSuccess: () => {
      setReportMessage('Report queued. It appears below when ready.')
      queryClient.invalidateQueries({ queryKey: ['scan-reports', scanId] })
    },
    onError: (err) => setReportMessage(errorText(err, 'Could not start the report.')),
  })

  if (isLoading) return <Skeleton className="h-96 w-full" />

  const runs = (phases ?? []).flatMap((p) => (p.runs ?? []).map((r) => ({ ...r, phase: p.phase_type })))
  const problemRuns = runs.filter((r) => r.status !== 'completed')
  const scanDuration = duration(scan?.started_at ?? null, scan?.completed_at ?? null)
  const openFindings = (patch: FindingSearch) => {
    setFindingFilters({ scan_id: scanId, ...patch })
    setTab('Findings')
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">{scan?.name}</h1>
          <p className="text-xs text-muted-foreground">Scan {scanId}</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={scan?.status === 'completed' ? 'default' : 'secondary'}>{scan?.status}</Badge>
          <StatusPill value={scan?.outcome === 'complete' ? 'completed' : active ? 'running' : 'completed_with_warnings'} />
          {active && !confirmStop && (
            <>
              <Button size="sm" variant="secondary" onClick={() => setConfirmStop('paused')}>Pause</Button>
              <Button size="sm" variant="destructive" onClick={() => setConfirmStop('cancelled')}>Cancel scan</Button>
            </>
          )}
          {active && confirmStop && (
            <>
              <span className="text-sm text-muted-foreground">
                {confirmStop === 'cancelled'
                  ? 'Cancel this scan? Running tools are stopped within a few seconds.'
                  : 'Pause this scan? It can be resumed later.'}
              </span>
              <Button size="sm" variant={confirmStop === 'cancelled' ? 'destructive' : 'secondary'}
                disabled={stop.isPending} onClick={() => stop.mutate(confirmStop)}>
                {confirmStop === 'cancelled' ? 'Yes, cancel' : 'Yes, pause'}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setConfirmStop(null)}>Keep running</Button>
            </>
          )}
        </div>
      </div>
      {stop.isError && <p className="text-sm text-red-400">The scan could not be stopped. Refresh and try again.</p>}

      <div role="tablist" className="flex flex-wrap gap-1 border-b border-border">
        {TABS.map((t) => (
          <button key={t} role="tab" type="button" aria-selected={tab === t} onClick={() => setTab(t)}
            className={cn('px-3 py-2 text-sm', tab === t ? 'border-b-2 border-accent font-medium text-foreground' : 'text-muted-foreground')}>
            {t}
            {t === 'Findings' && summary ? ` (${summary.total})` : ''}
            {t === 'Tool execution' && problemRuns.length ? ` (${problemRuns.length} issues)` : ''}
          </button>
        ))}
      </div>

      {tab === 'Overview' && (
        <div className="space-y-4">
          <div className="grid gap-4 md:grid-cols-4">
            <Card><CardHeader><CardTitle className="text-sm">Profile</CardTitle></CardHeader>
              <CardContent><p className="text-lg font-medium">{scan?.profile}</p>
                {scan?.coverage_reason === 'tech_targeted' && <p className="text-xs text-amber-400">Fast (technology-targeted)</p>}
              </CardContent></Card>
            <Card><CardHeader><CardTitle className="text-sm">Duration</CardTitle></CardHeader>
              <CardContent><p className="text-lg font-medium">{scanDuration || 'n/a'}</p>
                <p className="text-xs text-muted-foreground">
                  {scan?.started_at ? new Date(scan.started_at).toLocaleString() : ''}
                  {scan?.completed_at ? ` → ${new Date(scan.completed_at).toLocaleString()}` : ''}
                </p></CardContent></Card>
            <Card><CardHeader><CardTitle className="text-sm">Coverage</CardTitle></CardHeader>
              <CardContent><p className="text-lg font-medium">{scan?.outcome === 'complete' ? 'Complete' : 'Incomplete'}</p>
                <p className="text-xs text-muted-foreground">{scan?.coverage_reason ?? ''}</p></CardContent></Card>
            <Card><CardHeader><CardTitle className="text-sm">Stored findings</CardTitle></CardHeader>
              <CardContent><p className="text-lg font-medium">{summary?.total ?? '…'}</p>
                <p className="text-xs text-muted-foreground">
                  {summary ? `${summary.actionable} low or higher · ${summary.informational} informational` : ''}
                </p></CardContent></Card>
          </div>

          <Card>
            <CardHeader><CardTitle>Severity distribution</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <div className="flex flex-wrap gap-2">
                {(['critical', 'high', 'medium', 'low', 'info'] as const).map((s) => (
                  <button key={s} type="button" onClick={() => openFindings({ severity: s })}
                    className="rounded-md border border-border px-3 py-2 text-left text-sm hover:bg-surface-2">
                    <span className="block text-xs uppercase text-muted-foreground">{s}</span>
                    <span className="text-lg font-semibold">{summary?.by_severity[s] ?? 0}</span>
                  </button>
                ))}
              </div>
              <div className="text-sm text-muted-foreground">
                By tool:{' '}
                {summary && Object.entries(summary.by_tool).map(([tool, n], i) => (
                  <span key={tool}>{i > 0 && ' · '}
                    <button type="button" className="text-accent hover:underline" onClick={() => openFindings({ tool_source: tool })}>{tool} {n}</button>
                  </span>
                ))}
              </div>
              <Button size="sm" onClick={() => openFindings({})}>View all {summary?.total ?? ''} findings of this scan</Button>
              <p className="text-xs text-muted-foreground">
                Counts are stored finding rows for this scan only. Severities are the tools' own; zero findings do not establish that a target is secure.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Tool outcomes</CardTitle></CardHeader>
            <CardContent>
              {runs.length === 0 ? <p className="text-sm text-muted-foreground">No tool runs recorded yet.</p> : (
                <ul className="space-y-1 text-sm">
                  {runs.map((r, i) => (
                    <li key={`${r.phase}-${r.tool}-${i}`} className="flex flex-wrap items-center gap-2">
                      <StatusPill value={r.status} /><span className="font-medium">{r.tool}</span>
                      <span className="text-muted-foreground">{r.target}</span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {tab === 'Findings' && (
        <Card>
          <CardHeader><CardTitle>Findings of this scan</CardTitle></CardHeader>
          <CardContent>
            <FindingsTable filters={{ ...findingFilters, scan_id: scanId }} onChange={setFindingFilters}
              tools={summary ? Object.keys(summary.by_tool) : []} />
            <p className="mt-2 text-xs">
              <Link to="/findings" search={{ scan_id: scanId }} className="text-accent underline">Open in the Findings page</Link>
            </p>
          </CardContent>
        </Card>
      )}

      {tab === 'Recon & assets' && (
        <Card>
          <CardHeader><CardTitle>Recon and assets</CardTitle></CardHeader>
          <CardContent className="space-y-3 text-sm">
            {!assets ? <p className="text-muted-foreground">Loading…</p> : (
              <>
                <p>Target <span className="font-medium">{assets.target}</span>
                  {assets.passive_zone && <> · zone {assets.passive_zone}</>}
                  {assets.passive_names_observed != null && <> · {assets.passive_names_observed} names seen in passive sources</>}
                </p>
                <p className="text-muted-foreground">
                  In scope and probed: {assets.subdomains_in_scope.join(', ') || 'none'}. Only names allowed by the target's scope rules are probed.
                </p>
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>Host</TableHead><TableHead>Status</TableHead><TableHead>Title</TableHead>
                    <TableHead>Technology</TableHead><TableHead>Protections</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {assets.hosts.map((h) => (
                      <TableRow key={h.url}>
                        <TableCell className="font-medium">{h.url}</TableCell>
                        <TableCell>{h.status_code ?? '—'}</TableCell>
                        <TableCell>{h.title ?? '—'}</TableCell>
                        <TableCell className="text-xs">{(h.tech ?? []).join(', ') || '—'}</TableCell>
                        <TableCell className="text-xs">{(h.protections ?? []).join(', ') || 'none detected'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                <p className="text-xs text-muted-foreground">
                  Authorization: actions {String((assets.authorization.allowed_actions as string[] | undefined)?.join(', ') ?? 'n/a')} ·
                  methods {String((assets.authorization.http_methods as string[] | undefined)?.join(', ') ?? 'n/a')} ·
                  ports {String((assets.authorization.ports as number[] | undefined)?.join(', ') ?? 'n/a')} ·
                  {' '}{String(assets.authorization.max_requests_per_second ?? 'n/a')} req/s
                </p>
              </>
            )}
          </CardContent>
        </Card>
      )}

      {tab === 'Tool execution' && (
        <Card>
          <CardHeader><CardTitle>Tool execution</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            {!phases?.length && (
              <p className="text-sm text-muted-foreground">
                {active ? 'The first phase is running. Each phase appears here when it finishes.' : 'No phase records.'}
              </p>
            )}
            {phases?.map((phase) => (
              <div key={phase.id} className="space-y-2 rounded-md border border-border p-3">
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="font-medium">{PHASE_LABELS[phase.phase_type] ?? phase.phase_type}</span>
                  <StatusPill value={phase.outcome ?? phase.status} />
                  {phase.started_at && <span className="text-muted-foreground">{duration(phase.started_at, phase.completed_at)}</span>}
                  <span className="text-muted-foreground">· {phase.stored_findings ?? phase.findings_count} stored findings</span>
                </div>
                {phase.status === 'skipped' && phase.error_message && (
                  <p className="text-sm text-muted-foreground">Skipped: {phase.error_message}</p>
                )}
                {(phase.runs ?? []).length > 0 && (
                  <Table>
                    <TableHeader><TableRow>
                      <TableHead>Tool</TableHead><TableHead>Target</TableHead><TableHead>Status</TableHead>
                      <TableHead>Raw results</TableHead><TableHead>Progress</TableHead><TableHead>Reason</TableHead>
                    </TableRow></TableHeader>
                    <TableBody>
                      {(phase.runs ?? []).map((r, i) => (
                        <TableRow key={`${r.tool}-${i}`}>
                          <TableCell className="font-medium">{r.tool}</TableCell>
                          <TableCell className="text-xs">{r.target}</TableCell>
                          <TableCell><StatusPill value={r.status} /></TableCell>
                          <TableCell>{r.raw_results ?? '—'}</TableCell>
                          <TableCell className="text-xs">
                            {r.progress?.requests != null
                              ? `${r.progress.requests}${r.progress.total ? ` / ${r.progress.total}` : ''} requests${r.progress.errors ? `, ${r.progress.errors} errors` : ''}`
                              : '—'}
                          </TableCell>
                          <TableCell className="max-w-md text-xs text-muted-foreground">
                            {r.reason ?? r.error ?? ''}
                            {r.detail && <span className="block">{r.detail}</span>}
                            {(r.artifacts ?? []).map((a) => <span key={a.name} className="block font-mono">artifact: {a.name}</span>)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </div>
            ))}
            <p className="text-xs text-muted-foreground">
              Raw results are what a tool returned (hosts, subdomains, matches) and are not the same as stored findings.
              Nuclei runs keep their raw output (artifact names above) in the scan's output folder; runs from before this change have no artifacts.
            </p>
          </CardContent>
        </Card>
      )}

      {tab === 'Coverage & limitations' && (
        <div className="space-y-4">
          <Card>
            <CardHeader><CardTitle>{scan?.outcome === 'complete' ? 'Complete coverage' : 'Incomplete coverage'}</CardTitle></CardHeader>
            <CardContent className="space-y-2 text-sm">
              <p className="text-muted-foreground">Coverage records which required tools completed. Zero findings do not establish that a target is secure.</p>
              {scan?.coverage_reason === 'tech_targeted' && (
                <p className="text-amber-400">Fast scan: nuclei ran only the templates for the detected technology plus general misconfiguration and exposure checks. Run a full scan for complete coverage.</p>
              )}
              {!scan?.coverage?.length && <p>Coverage evidence is unavailable for this scan.</p>}
              <ul className="space-y-1">
                {scan?.coverage?.map((run, index) => (
                  <li key={`${run.phase}-${run.tool}-${index}`}>
                    <span className="font-medium">{run.tool}</span> ({run.phase}) — {run.state}
                    {run.required ? ' · required' : ' · optional'}
                    {run.reason_code && <span> · {run.reason_code}</span>}
                  </li>
                ))}
              </ul>
              {problemRuns.length > 0 && (
                <ul className="list-disc pl-5">
                  {problemRuns.map((r, i) => (
                    <li key={i}><span className="font-medium">{r.tool}</span> on {r.target}: {r.status.replace(/_/g, ' ')}{r.reason ? ` — ${r.reason}` : r.error ? ` — ${r.error}` : ''}</li>
                  ))}
                </ul>
              )}
              <p className="text-muted-foreground">Testing was unauthenticated: functionality behind login was not assessed.</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>OWASP Top 10:2025</CardTitle></CardHeader>
            <CardContent>
              <p className="mb-2 text-xs text-muted-foreground">States describe what this scan actually ran. Running a scanner does not by itself cover a category.</p>
              {!owasp ? <p className="text-sm text-muted-foreground">Loading…</p> : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>Category</TableHead><TableHead>State</TableHead><TableHead>Findings</TableHead><TableHead>Checks and limitations</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {owasp.map((row) => (
                      <TableRow key={row.id}>
                        <TableCell className="font-medium">{row.name}</TableCell>
                        <TableCell><StatusPill value={row.state} /></TableCell>
                        <TableCell>{row.findings}</TableCell>
                        <TableCell className="max-w-xl text-xs text-muted-foreground">{row.checks} {row.limitations}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {tab === 'Reports' && (
        <Card>
          <CardHeader><CardTitle>Reports</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Reports can be generated for partial scans; they list failed and skipped checks under limitations.
            </p>
            <div className="grid gap-2 md:grid-cols-4">
              {REPORT_OPTIONS.map((o) => (
                <button key={o.type} type="button" disabled={generate.isPending} onClick={() => generate.mutate(o.type)}
                  className="rounded-md border border-border p-3 text-left hover:bg-surface-2 disabled:opacity-50">
                  <span className="block text-sm font-medium">{o.label}</span>
                  <span className="block text-xs text-muted-foreground">{o.hint}</span>
                </button>
              ))}
            </div>
            {reportMessage && <p className="text-sm">{reportMessage}</p>}
            <p className="text-xs"><Link to="/reports" search={{ scan_id: scanId }} className="text-accent underline">Other report formats</Link></p>
            {reports.length === 0 ? <p className="text-sm text-muted-foreground">No reports for this scan yet.</p> : (
              <Table>
                <TableHeader><TableRow>
                  <TableHead>Created</TableHead><TableHead>Type</TableHead><TableHead>Status</TableHead><TableHead>File</TableHead>
                </TableRow></TableHeader>
                <TableBody>
                  {reports.map((row) => (
                    <TableRow key={row.id}>
                      <TableCell className="text-xs">{new Date(row.created_at).toLocaleString()}</TableCell>
                      <TableCell>{row.report_type}</TableCell>
                      <TableCell>{row.status}</TableCell>
                      <TableCell>
                        {row.status === 'completed' ? (
                          <Button variant="ghost" size="sm"
                            onClick={() => reportFilesApi.download(row.id, reportFilename(row)).catch((err) => setReportMessage(errorText(err, 'The report file is not available.')))}>
                            Download
                          </Button>
                        ) : row.status === 'failed' ? (
                          <span className="text-xs text-red-400">Failed: {row.error_message ?? 'unknown error'}</span>
                        ) : <span className="text-xs text-muted-foreground">Working…</span>}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
