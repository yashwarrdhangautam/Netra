import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { RefreshCw, ShieldCheck } from 'lucide-react'
import { BBPlatform, bugBountyApi } from '@/api/bugbounty'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { StatusPill } from '@/components/bugbounty/StatusAtoms'
import { formatRelativeTime } from '@/utils/formatters'

const platforms: BBPlatform[] = ['hackerone', 'bugcrowd', 'intigriti', 'private']

export function BBPrograms() {
  const client = useQueryClient()
  const [platform, setPlatform] = useState<BBPlatform>('hackerone')
  const [handle, setHandle] = useState('')
  const [name, setName] = useState('')
  const [message, setMessage] = useState<string | null>(null)

  const programs = useQuery({ queryKey: ['bb-programs'], queryFn: bugBountyApi.programs })
  const createProgram = useMutation({
    mutationFn: () => bugBountyApi.createProgram({ platform, handle, name: name || undefined, auto_sync_scope: true }),
    onSuccess: () => {
      setHandle('')
      setName('')
      setMessage('Program registered.')
      client.invalidateQueries({ queryKey: ['bb-programs'] })
    },
  })
  const syncScope = useMutation({
    mutationFn: bugBountyApi.syncScope,
    onSuccess: (diff) => {
      setMessage(diff.warning || `Scope sync complete. Added ${diff.added.length}, removed ${diff.removed.length}, unchanged ${diff.unchanged_count}.`)
      client.invalidateQueries({ queryKey: ['bb-programs'] })
    },
  })

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Programs</h1>
        <p className="text-sm text-muted-foreground">Register, sync, and inspect bug bounty programs.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Add Program</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-[180px_1fr_1fr_auto]">
            <select value={platform} onChange={(event) => setPlatform(event.target.value as BBPlatform)} className="rounded border border-border bg-surface-2 px-3 py-2 text-sm">
              {platforms.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
            <input value={handle} onChange={(event) => setHandle(event.target.value)} placeholder="handle, e.g. shopify" className="rounded border border-border bg-surface-2 px-3 py-2 font-mono text-sm" />
            <input value={name} onChange={(event) => setName(event.target.value)} placeholder="display name (optional)" className="rounded border border-border bg-surface-2 px-3 py-2 text-sm" />
            <Button disabled={!handle || createProgram.isPending} onClick={() => createProgram.mutate()}>
              <ShieldCheck className="mr-2 h-4 w-4" />
              Add
            </Button>
          </div>
          {message ? <p className="mt-3 text-sm text-muted-foreground">{message}</p> : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Program Registry</CardTitle>
        </CardHeader>
        <CardContent>
          {programs.isLoading ? (
            <Skeleton className="h-48 w-full" />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="py-2">Platform</th>
                    <th>Handle</th>
                    <th>Name</th>
                    <th>Payout</th>
                    <th>Scope</th>
                    <th>Assets</th>
                    <th>Open</th>
                    <th>Last synced</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {programs.data?.map((program) => (
                    <tr key={program.id} className="border-t border-border">
                      <td className="py-2"><StatusPill>{program.platform}</StatusPill></td>
                      <td className="font-mono">{program.handle}</td>
                      <td>{program.name}</td>
                      <td className="font-mono tabular-nums">{program.payout_min || 0}-{program.payout_max || 0} {program.currency}</td>
                      <td className="font-mono tabular-nums">{program.counts.scope_rules}</td>
                      <td className="font-mono tabular-nums">{program.counts.assets}</td>
                      <td className="font-mono tabular-nums">{program.counts.findings_open}</td>
                      <td className="text-muted-foreground">{program.scope_synced_at ? formatRelativeTime(program.scope_synced_at) : 'never'}</td>
                      <td className="text-right">
                        <Button size="sm" variant="outline" disabled={syncScope.isPending} onClick={() => syncScope.mutate(program.id)}>
                          <RefreshCw className="mr-2 h-4 w-4" />
                          Sync
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
