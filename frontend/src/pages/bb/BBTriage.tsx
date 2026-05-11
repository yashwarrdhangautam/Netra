import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { EyeOff } from 'lucide-react'
import { bugBountyApi } from '@/api/bugbounty'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { SeverityBadge, StatusPill } from '@/components/bugbounty/StatusAtoms'
import { formatRelativeTime } from '@/utils/formatters'

export function BBTriage() {
  const [programId, setProgramId] = useState('')
  const [includeVetoed, setIncludeVetoed] = useState(false)
  const programs = useQuery({ queryKey: ['bb-programs'], queryFn: bugBountyApi.programs })
  const triage = useQuery({
    queryKey: ['bb-triage', programId, includeVetoed],
    queryFn: () => bugBountyApi.triage({ programId: programId || undefined, includeVetoed, graphAware: true }),
  })

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Triage Queue</h1>
        <p className="text-sm text-muted-foreground">Ranked by BountyHunter composite, with Skeptic vetoes hidden by default.</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Filters</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <select value={programId} onChange={(event) => setProgramId(event.target.value)} className="rounded border border-border bg-surface-2 px-3 py-2 text-sm">
            <option value="">All programs</option>
            {programs.data?.map((program) => <option key={program.id} value={program.id}>{program.platform}/{program.handle}</option>)}
          </select>
          <label className="inline-flex items-center gap-2 text-sm text-muted-foreground">
            <input type="checkbox" checked={includeVetoed} onChange={(event) => setIncludeVetoed(event.target.checked)} />
            Include Skeptic vetoes
          </label>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Findings</CardTitle>
        </CardHeader>
        <CardContent>
          {triage.isLoading ? (
            <Skeleton className="h-64 w-full" />
          ) : (
            <div className="space-y-2">
              {triage.data?.map((finding) => {
                const composite = Number(finding.bounty_hunter.composite || 0)
                const tier = String(finding.bounty_hunter.tier || 'review')
                return (
                  <div key={finding.id} className="rounded border border-border bg-surface-2 p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={finding.severity} cvss={finding.cvss} />
                      <span className="font-medium">{finding.title}</span>
                      <span className="font-mono text-xs text-muted-foreground">{finding.asset || 'unknown asset'}</span>
                      <StatusPill>{tier}</StatusPill>
                      <span className="ml-auto font-mono text-sm tabular-nums">{composite.toFixed(1)}</span>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                      <span>{finding.vuln_class}</span>
                      <span>{formatRelativeTime(finding.created_at)}</span>
                      {finding.dedup.exact ? <span className="text-red-300">dup flagged</span> : null}
                      {finding.dedup.similar.length ? <span className="text-amber-300">similar: {finding.dedup.similar.length}</span> : null}
                      {finding.skeptic_vetoed ? <span className="inline-flex items-center gap-1 text-red-300"><EyeOff className="h-3 w-3" /> vetoed</span> : null}
                    </div>
                    {finding.bounty_hunter.rationale ? <p className="mt-2 text-sm text-muted-foreground">{String(finding.bounty_hunter.rationale)}</p> : null}
                    <div className="mt-3">
                      <Link to="/bb/findings/$findingId" params={{ findingId: finding.id }}>
                        <span className="inline-flex h-8 items-center rounded border border-border px-3 text-xs font-medium text-muted-foreground hover:bg-surface-3">
                          Open in PoC Lab
                        </span>
                      </Link>
                    </div>
                  </div>
                )
              })}
              {!triage.data?.length ? <p className="text-sm text-muted-foreground">No triage rows match the current filters.</p> : null}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
