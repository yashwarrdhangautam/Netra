import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { Activity, AlertTriangle, Database, FileText, Search, ShieldCheck } from 'lucide-react'
import { bugBountyApi } from '@/api/bugbounty'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { CommandBlock, StatusPill } from '@/components/bugbounty/StatusAtoms'
import { formatRelativeTime } from '@/utils/formatters'

export function BBConsole() {
  const { data, isLoading } = useQuery({
    queryKey: ['bb-dashboard'],
    queryFn: bugBountyApi.dashboard,
    refetchInterval: 30000,
  })
  const trends = useQuery({
    queryKey: ['bb-trends', 7],
    queryFn: () => bugBountyApi.trends(7),
    refetchInterval: 300000,
  })

  const degraded = data?.doctor.filter((check) => check.status !== 'ok') || []
  const metrics = [
    { label: 'Active programs', value: data?.active_programs, Icon: ShieldCheck },
    { label: 'Scope rules', value: data?.scope_rules, Icon: Search },
    { label: 'Assets', value: data?.assets, Icon: Database },
    { label: 'Open findings', value: data?.open_findings, Icon: AlertTriangle },
    { label: 'Drafts', value: data?.submissions_draft, Icon: FileText },
  ]

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">NETRA-BB Console</h1>
          <p className="text-sm text-muted-foreground">Scope-first bug bounty operations.</p>
        </div>
        <Link to="/bb/hunts">
          <span className="inline-flex h-9 items-center gap-2 rounded-md bg-accent px-3 text-sm font-medium text-white">
            <Activity className="h-4 w-4" />
            Run hunt
          </span>
        </Link>
      </div>

      <div className="grid gap-3 md:grid-cols-5">
        {metrics.map(({ label, value, Icon }) => (
          <Card key={label}>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm text-muted-foreground">
                <Icon className="h-4 w-4" />
                {label}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? <Skeleton className="h-8 w-16" /> : <div className="font-mono text-2xl tabular-nums">{Number(value || 0)}</div>}
            </CardContent>
          </Card>
        ))}
      </div>

      {data && data.out_of_scope_blocks_24h > 0 ? (
        <div className="rounded border border-red-800 bg-red-950/40 p-3 text-sm text-red-100">
          {data.out_of_scope_blocks_24h} out-of-scope attempts blocked in the last 24h.
          <Link to="/bb/audit" className="ml-2 underline">Review audit</Link>
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[1fr_360px]">
        <Card>
          <CardHeader>
            <CardTitle>Recent Hunts</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-36 w-full" />
            ) : data?.recent_hunts.length ? (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="text-left text-xs uppercase text-muted-foreground">
                    <tr>
                      <th className="py-2">Name</th>
                      <th>Status</th>
                      <th>Mode</th>
                      <th>Assets</th>
                      <th>Findings</th>
                      <th>Blocks</th>
                      <th>Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.recent_hunts.map((hunt) => (
                      <tr key={hunt.id} className="border-t border-border">
                        <td className="py-2 font-medium">{hunt.name}</td>
                        <td><StatusPill>{hunt.status}</StatusPill></td>
                        <td className="text-xs text-muted-foreground">{hunt.mode}{hunt.dry_run ? ' / dry' : ''}</td>
                        <td className="font-mono tabular-nums">{hunt.assets_discovered}</td>
                        <td className="font-mono tabular-nums">{hunt.findings_count}</td>
                        <td className={hunt.blocked_count ? 'font-mono tabular-nums text-red-400' : 'font-mono tabular-nums text-green-400'}>{hunt.blocked_count}</td>
                        <td className="text-muted-foreground">{formatRelativeTime(hunt.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="space-y-3 text-sm text-muted-foreground">
                <p>No hunts have run yet.</p>
                <CommandBlock command="netra-bb hunt --program <handle> --profile passive" />
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Readiness</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-36 w-full" />
            ) : degraded.length ? (
              <div className="space-y-2">
                {degraded.slice(0, 6).map((check) => (
                  <div key={check.name} className="rounded border border-border bg-surface-2 p-2">
                    <div className="flex items-center justify-between text-sm">
                      <span className="font-medium">{check.name}</span>
                      <span className={check.status === 'error' ? 'text-red-400' : 'text-amber-400'}>{check.status}</span>
                    </div>
                    <p className="mt-1 text-xs text-muted-foreground">{check.detail}</p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">Doctor reports all required checks passing.</p>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Learning Trends</CardTitle>
          </CardHeader>
          <CardContent>
            {trends.isLoading ? (
              <Skeleton className="h-36 w-full" />
            ) : trends.data ? (
              <div className="space-y-3 text-sm">
                <div className="grid grid-cols-3 gap-2">
                  <div className="rounded border border-border bg-surface-2 p-3">
                    <div className="text-xs text-muted-foreground">Reports</div>
                    <div className="font-mono text-lg tabular-nums">{trends.data.total_reports}</div>
                  </div>
                  <div className="rounded border border-border bg-surface-2 p-3">
                    <div className="text-xs text-muted-foreground">Writeups</div>
                    <div className="font-mono text-lg tabular-nums">{trends.data.total_writeups}</div>
                  </div>
                  <div className="rounded border border-border bg-surface-2 p-3">
                    <div className="text-xs text-muted-foreground">Advisories</div>
                    <div className="font-mono text-lg tabular-nums">{trends.data.total_advisories}</div>
                  </div>
                </div>
                <div>
                  <div className="mb-2 text-xs uppercase text-muted-foreground">Top vuln classes</div>
                  <div className="space-y-2">
                    {trends.data.top_vuln_classes.slice(0, 5).map((item) => (
                      <div key={item.name} className="flex items-center justify-between rounded border border-border bg-surface-2 px-3 py-2">
                        <span>{item.name}</span>
                        <span className="font-mono tabular-nums text-muted-foreground">{item.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No trend data yet.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top Programs</CardTitle>
          </CardHeader>
          <CardContent>
            {trends.isLoading ? (
              <Skeleton className="h-36 w-full" />
            ) : trends.data?.top_programs.length ? (
              <div className="space-y-2 text-sm">
                {trends.data.top_programs.slice(0, 5).map((item) => (
                  <div key={item.name} className="flex items-center justify-between rounded border border-border bg-surface-2 px-3 py-2">
                    <span>{item.name}</span>
                    <span className="font-mono tabular-nums text-muted-foreground">{item.count}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">Program trends will appear after the corpus has a few ingests.</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
