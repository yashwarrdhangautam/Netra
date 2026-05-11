import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { bugBountyApi } from '@/api/bugbounty'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { ScopeVerdictChip, StatusPill } from '@/components/bugbounty/StatusAtoms'
import { formatRelativeTime } from '@/utils/formatters'

export function BBScope() {
  const [programId, setProgramId] = useState('')
  const [target, setTarget] = useState('')
  const programs = useQuery({ queryKey: ['bb-programs'], queryFn: bugBountyApi.programs })
  const rules = useQuery({
    queryKey: ['bb-scope-rules', programId],
    queryFn: () => bugBountyApi.scopeRules(programId),
    enabled: Boolean(programId),
  })
  const blocks = useQuery({ queryKey: ['bb-scope-blocks'], queryFn: bugBountyApi.scopeBlocks })
  const checkScope = useMutation({
    mutationFn: () => bugBountyApi.checkScope(programId, target),
  })

  const selectedProgram = programs.data?.find((program) => program.id === programId)

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Scope Center</h1>
        <p className="text-sm text-muted-foreground">The safety boundary for every BB action.</p>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_420px]">
        <Card>
          <CardHeader>
            <CardTitle>Rules</CardTitle>
          </CardHeader>
          <CardContent>
            <select value={programId} onChange={(event) => setProgramId(event.target.value)} className="mb-3 w-full rounded border border-border bg-surface-2 px-3 py-2 text-sm">
              <option value="">Select program</option>
              {programs.data?.map((program) => <option key={program.id} value={program.id}>{program.platform}/{program.handle}</option>)}
            </select>
            {selectedProgram?.scope_synced_at ? (
              <p className="mb-3 text-xs text-muted-foreground">Last synced {formatRelativeTime(selectedProgram.scope_synced_at)}</p>
            ) : null}
            {rules.isLoading ? (
              <Skeleton className="h-64 w-full" />
            ) : (
              <div className="max-h-[620px] overflow-auto">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-surface text-left text-xs uppercase text-muted-foreground">
                    <tr>
                      <th className="py-2">Type</th>
                      <th>Asset</th>
                      <th>Pattern</th>
                      <th>Cap</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rules.data?.map((rule) => (
                      <tr key={rule.id} className="border-t border-border">
                        <td className="py-2"><StatusPill className={rule.rule_type === 'in' ? 'text-green-400' : 'text-red-400'}>{rule.rule_type}</StatusPill></td>
                        <td>{rule.asset_type}</td>
                        <td className="font-mono">{rule.pattern}</td>
                        <td className="text-muted-foreground">{rule.severity_cap || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Checker</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://api.example.com/path" className="w-full rounded border border-border bg-surface-2 px-3 py-2 font-mono text-sm" />
              <Button disabled={!programId || !target || checkScope.isPending} onClick={() => checkScope.mutate()}>
                <Search className="mr-2 h-4 w-4" />
                Check
              </Button>
              {checkScope.data ? (
                <div className="space-y-3 rounded border border-border bg-surface-2 p-3">
                  <div className="flex items-center justify-between">
                    <ScopeVerdictChip allowed={checkScope.data.allowed} />
                    <span className="text-xs text-muted-foreground">{checkScope.data.severity_cap || 'no cap'}</span>
                  </div>
                  <p className="text-sm">{checkScope.data.reason}</p>
                  <pre className="max-h-64 overflow-auto rounded bg-surface p-2 font-mono text-xs text-muted-foreground">{JSON.stringify(checkScope.data.parsed, null, 2)}</pre>
                </div>
              ) : null}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Recent Blocks</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {blocks.data?.slice(0, 8).map((block) => (
                  <div key={block.id} className="rounded border border-border bg-surface-2 p-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-red-300">{block.target || 'unknown target'}</span>
                      <span className="text-muted-foreground">{formatRelativeTime(block.timestamp)}</span>
                    </div>
                    <p className="mt-1 text-muted-foreground">{block.reason || block.tool}</p>
                  </div>
                ))}
                {!blocks.data?.length ? <p className="text-sm text-muted-foreground">No scope blocks in the current audit window.</p> : null}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
