import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { bugBountyApi } from '@/api/bugbounty'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { StatusPill } from '@/components/bugbounty/StatusAtoms'

export function BBDoctor() {
  const doctor = useQuery({ queryKey: ['bb-doctor'], queryFn: bugBountyApi.doctor })
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Doctor</h1>
          <p className="text-sm text-muted-foreground">Operational readiness for bug bounty workflows.</p>
        </div>
        <Button variant="outline" onClick={() => doctor.refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" />
          Refresh
        </Button>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Checks</CardTitle>
        </CardHeader>
        <CardContent>
          {doctor.isLoading ? (
            <Skeleton className="h-64 w-full" />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="py-2">Check</th>
                    <th>Status</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {doctor.data?.map((check) => (
                    <tr key={check.name} className="border-t border-border">
                      <td className="py-2 font-medium">{check.name}</td>
                      <td>
                        <StatusPill className={check.status === 'ok' ? 'text-green-400' : check.status === 'error' ? 'text-red-400' : 'text-amber-400'}>
                          {check.status}
                        </StatusPill>
                      </td>
                      <td className="text-muted-foreground">{check.detail}</td>
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
