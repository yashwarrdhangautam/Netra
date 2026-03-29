import { useQuery } from '@tanstack/react-query'
import { findingsApi } from '@/api/findings'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table'
import { getSeverityColor } from '@/utils/formatters'
import type { FindingList } from '@/types'

export function FindingsList() {
  const { data, isLoading } = useQuery({
    queryKey: ['findings'],
    queryFn: () => findingsApi.list({ page: 1, per_page: 50 }),
  })

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Findings</h1>

      <Card>
        <CardHeader>
          <CardTitle>All Findings ({data?.total || 0})</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-muted-foreground">Loading...</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Tool</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data?.items.map((finding: FindingList) => (
                  <TableRow key={finding.id}>
                    <TableCell>
                      <Badge className={getSeverityColor(finding.severity)}>
                        {finding.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-medium">{finding.title}</TableCell>
                    <TableCell>{finding.status}</TableCell>
                    <TableCell className="text-muted-foreground">{finding.tool_source}</TableCell>
                    <TableCell className="text-muted-foreground">{new Date(finding.created_at).toLocaleDateString()}</TableCell>
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
