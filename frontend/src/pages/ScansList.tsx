import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { scansApi } from '@/api/scans'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table'
import { formatDate, formatRelativeTime } from '@/utils/formatters'
import type { ScanList, ScanStatus } from '@/types'

export function ScansList() {
  const [statusFilter, setStatusFilter] = useState<ScanStatus | ''>('')

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['scans', { status: statusFilter || undefined }],
    queryFn: () => scansApi.list({ status: statusFilter || undefined }),
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Scans</h1>
        <Button onClick={() => refetch()}>Refresh</Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>All Scans</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-muted-foreground">Loading...</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Profile</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data?.items.map((scan: ScanList) => (
                  <TableRow key={scan.id}>
                    <TableCell className="font-medium">{scan.name}</TableCell>
                    <TableCell>
                      <Badge variant={scan.status === 'completed' ? 'default' : 'secondary'}>
                        {scan.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{scan.profile}</TableCell>
                    <TableCell className="text-muted-foreground">{formatRelativeTime(scan.created_at)}</TableCell>
                    <TableCell>
                      <Button variant="ghost" size="sm">View</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
