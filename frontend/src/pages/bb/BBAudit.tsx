import { useQuery } from '@tanstack/react-query'
import { bugBountyApi } from '@/api/bugbounty'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { ScopeVerdictChip } from '@/components/bugbounty/StatusAtoms'
import { formatRelativeTime } from '@/utils/formatters'

export function BBAudit() {
  const blocks = useQuery({ queryKey: ['bb-scope-blocks'], queryFn: bugBountyApi.scopeBlocks, refetchInterval: 30000 })
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Audit Log</h1>
        <p className="text-sm text-muted-foreground">Safety-relevant bug bounty events.</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Scope Blocks</CardTitle>
        </CardHeader>
        <CardContent>
          {blocks.isLoading ? (
            <Skeleton className="h-56 w-full" />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="py-2">Decision</th>
                    <th>Target</th>
                    <th>Tool</th>
                    <th>Reason</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {blocks.data?.map((block) => (
                    <tr key={block.id} className="border-t border-border">
                      <td className="py-2"><ScopeVerdictChip allowed={false} /></td>
                      <td className="font-mono">{block.target || 'unknown'}</td>
                      <td>{block.tool}</td>
                      <td className="text-muted-foreground">{block.reason || '-'}</td>
                      <td className="text-muted-foreground">{formatRelativeTime(block.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!blocks.data?.length ? <p className="mt-3 text-sm text-muted-foreground">0 scope blocks in the current window.</p> : null}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
