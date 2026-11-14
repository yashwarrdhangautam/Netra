import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { bugBountyApi } from '@/api/bugbounty'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table'
import { ScopeVerdictChip } from '@/components/bugbounty/StatusAtoms'
import { formatRelativeTime } from '@/utils/formatters'
import { cn } from '@/utils/formatters'

type Tab = 'scope' | 'actions'

export function BBAudit() {
  const [tab, setTab] = useState<Tab>('scope')
  const blocks = useQuery({
    queryKey: ['bb-scope-blocks'],
    queryFn: bugBountyApi.scopeBlocks,
    refetchInterval: 30000,
    enabled: tab === 'scope',
  })
  const actions = useQuery({
    queryKey: ['bb-ui-actions'],
    queryFn: bugBountyApi.uiActions,
    refetchInterval: 30000,
    enabled: tab === 'actions',
  })

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Audit log</h1>
        <p className="text-sm text-muted-foreground">Safety-relevant bug bounty events.</p>
      </div>

      <div role="tablist" className="flex gap-2 border-b border-border">
        {(['scope', 'actions'] as Tab[]).map((t) => (
          <button
            key={t}
            role="tab"
            aria-selected={tab === t}
            onClick={() => setTab(t)}
            className={cn(
              'px-3 py-2 text-sm',
              tab === t ? 'border-b-2 border-accent font-medium text-foreground' : 'text-muted-foreground hover:text-foreground'
            )}
          >
            {t === 'scope' ? 'Scope blocks' : 'UI actions'}
          </button>
        ))}
      </div>

      {tab === 'scope' && (
        <Card>
          <CardHeader>
            <CardTitle>Scope blocks</CardTitle>
          </CardHeader>
          <CardContent>
            {blocks.isLoading ? (
              <Skeleton className="h-56 w-full" />
            ) : (blocks.data?.length ?? 0) === 0 ? (
              <p className="text-sm text-muted-foreground">0 scope blocks. Good.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Decision</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Tool</TableHead>
                    <TableHead>Reason</TableHead>
                    <TableHead>Time</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {blocks.data?.map((b) => (
                    <TableRow key={b.id}>
                      <TableCell>
                        <ScopeVerdictChip allowed={b.decision !== 'blocked'} />
                      </TableCell>
                      <TableCell className="font-mono text-xs">{b.target ?? '—'}</TableCell>
                      <TableCell>{b.tool}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{b.reason ?? '—'}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatRelativeTime(b.timestamp)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      {tab === 'actions' && (
        <Card>
          <CardHeader>
            <CardTitle>State-changing actions</CardTitle>
          </CardHeader>
          <CardContent>
            {actions.isLoading ? (
              <Skeleton className="h-56 w-full" />
            ) : (actions.data?.length ?? 0) === 0 ? (
              <p className="text-sm text-muted-foreground">No recorded actions yet.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>When</TableHead>
                    <TableHead>Actor</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Result</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {actions.data?.map((a, i) => (
                    <TableRow key={String(a.id ?? i)}>
                      <TableCell className="text-xs text-muted-foreground">
                        {a.ts ? formatRelativeTime(String(a.ts)) : '—'}
                      </TableCell>
                      <TableCell>{String(a.actor_email ?? a.actor_id ?? 'system')}</TableCell>
                      <TableCell className="font-mono text-xs">{String(a.action ?? '')}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {[a.target_type, a.target_id].filter(Boolean).map(String).join(': ') || '—'}
                      </TableCell>
                      <TableCell>{String(a.result_code ?? '')}</TableCell>
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
