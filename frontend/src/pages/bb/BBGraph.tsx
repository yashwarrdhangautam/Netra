import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { GitBranch, RefreshCw } from 'lucide-react'
import { bugBountyApi } from '@/api/bugbounty'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { StatusPill } from '@/components/bugbounty/StatusAtoms'

export function BBGraph() {
  const [programId, setProgramId] = useState('')
  const programs = useQuery({ queryKey: ['bb-programs'], queryFn: bugBountyApi.programs })
  const graph = useQuery({
    queryKey: ['bb-program-graph', programId],
    queryFn: () => bugBountyApi.programGraph(programId),
    enabled: Boolean(programId),
  })
  const codebase = useQuery({ queryKey: ['bb-codebase-graph'], queryFn: bugBountyApi.codebaseGraph })
  const reindex = useMutation({ mutationFn: () => bugBountyApi.reindexGraph('codebase') })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Graph View</h1>
          <p className="text-sm text-muted-foreground">Hierarchical program graph and cached Graphify codebase graph.</p>
        </div>
        <Button variant="outline" onClick={() => reindex.mutate()}>
          <RefreshCw className="mr-2 h-4 w-4" />
          Reindex codebase
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Program Graph</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <select value={programId} onChange={(event) => setProgramId(event.target.value)} className="rounded border border-border bg-surface-2 px-3 py-2 text-sm">
            <option value="">Select program</option>
            {programs.data?.map((program) => <option key={program.id} value={program.id}>{program.platform}/{program.handle}</option>)}
          </select>
          {graph.isLoading ? <Skeleton className="h-48 w-full" /> : graph.data ? <GraphTable nodes={graph.data.nodes} edges={graph.data.edges} /> : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Codebase Graph</CardTitle>
        </CardHeader>
        <CardContent>
          {codebase.isLoading ? <Skeleton className="h-32 w-full" /> : (
            <div className="flex flex-wrap gap-3 text-sm">
              <StatusPill><GitBranch className="mr-1 h-3 w-3" /> nodes {codebase.data?.nodes?.length || 0}</StatusPill>
              <StatusPill>edges {codebase.data?.edges?.length || 0}</StatusPill>
              {codebase.data?.warning ? <span className="text-muted-foreground">{codebase.data.warning}</span> : null}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function GraphTable({ nodes, edges }: { nodes: Array<Record<string, unknown>>; edges: Array<Record<string, unknown>> }) {
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <div>
        <h3 className="mb-2 text-sm font-medium">Nodes</h3>
        <div className="max-h-72 overflow-auto rounded border border-border">
          {nodes.map((node) => (
            <div key={String(node.id)} className="border-b border-border px-3 py-2 text-sm last:border-b-0">
              <span className="font-mono text-xs text-muted-foreground">{String(node.type || 'node')}</span>
              <span className="ml-2">{String(node.label || node.id)}</span>
            </div>
          ))}
        </div>
      </div>
      <div>
        <h3 className="mb-2 text-sm font-medium">Edges</h3>
        <div className="max-h-72 overflow-auto rounded border border-border">
          {edges.map((edge, index) => (
            <div key={index} className="border-b border-border px-3 py-2 font-mono text-xs text-muted-foreground last:border-b-0">
              {String(edge.source)} -[{String(edge.rel || 'rel')}]-&gt; {String(edge.target)}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
