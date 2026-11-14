import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { auditApi } from '@/api/platform'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table'
import { cn } from '@/utils/formatters'

const PAGE = 50
const INPUT = cn(
  'rounded-md border border-border bg-surface-2 px-3 py-2 text-sm text-foreground',
  'focus:outline-none focus:ring-2 focus:ring-accent'
)

export function Audit() {
  const [action, setAction] = useState('')
  const [applied, setApplied] = useState('')
  const [offset, setOffset] = useState(0)

  const { data, isLoading, error } = useQuery({
    queryKey: ['audit', applied, offset],
    queryFn: () => auditApi.list({ limit: PAGE, offset, action: applied || undefined }),
  })

  if (error) {
    return (
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold">Audit log</h1>
        <p className="text-sm text-red-400">Only admins can read the audit log.</p>
      </div>
    )
  }

  const total = data?.total ?? 0
  const from = total === 0 ? 0 : offset + 1
  const to = Math.min(offset + PAGE, total)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Audit log</h1>
        <p className="text-sm text-muted-foreground">
          Who changed what, and when: accounts, targets, settings and sign-in security changes.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Events</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault()
              setOffset(0)
              setApplied(action.trim())
            }}
          >
            <input
              className={cn(INPUT, 'flex-1')}
              placeholder="Filter by action, e.g. user. or target."
              aria-label="Filter by action"
              value={action}
              onChange={(e) => setAction(e.target.value)}
            />
            <Button type="submit" variant="outline">Filter</Button>
          </form>

          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : total === 0 ? (
            <p className="text-sm text-muted-foreground">No matching events.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead>Who</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Object</TableHead>
                  <TableHead>Detail</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data?.items.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell className="whitespace-nowrap text-xs">
                      {new Date(e.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell>{e.actor_email ?? 'system'}</TableCell>
                    <TableCell className="font-mono text-xs">{e.action}</TableCell>
                    <TableCell className="text-xs">
                      {e.resource_type}
                      {e.resource_id ? `: ${e.resource_id}` : ''}
                    </TableCell>
                    <TableCell className="max-w-xs truncate font-mono text-xs text-muted-foreground">
                      {e.detail && Object.keys(e.detail).length > 0 ? JSON.stringify(e.detail) : '—'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>
              {from}–{to} of {total}
            </span>
            <div className="space-x-2">
              <Button variant="outline" size="sm" disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</Button>
              <Button variant="outline" size="sm" disabled={offset + PAGE >= total}
                onClick={() => setOffset(offset + PAGE)}>Next</Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
