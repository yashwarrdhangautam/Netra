import { useParams } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { scansApi } from '@/api/scans'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Skeleton } from '@/components/ui/Skeleton'

export function ScanDetail() {
  const { scanId } = useParams({ strict: false })

  const { data: scan, isLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId as string),
    enabled: !!scanId,
  })

  if (isLoading) {
    return <Skeleton className="h-96 w-full" />
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{scan?.name}</h1>
        <Badge variant={scan?.status === 'completed' ? 'default' : 'secondary'}>
          {scan?.status}
        </Badge>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Profile</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-lg font-medium">{scan?.profile}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Started</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-lg font-medium">{scan?.started_at ? new Date(scan.started_at).toLocaleString() : 'N/A'}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Completed</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-lg font-medium">{scan?.completed_at ? new Date(scan.completed_at).toLocaleString() : 'N/A'}</p>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
