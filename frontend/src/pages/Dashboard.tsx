import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { CheckCircle, AlertCircle, Clock } from 'lucide-react'
import { scansApi } from '@/api/scans'
import { findingsApi } from '@/api/findings'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table'
import { Skeleton } from '@/components/ui/Skeleton'
import { EmptyState } from '@/components/shared/EmptyState'
import { formatRelativeTime } from '@/utils/formatters'
import type { ScanList } from '@/types'

const COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#3b82f6',
  info: '#6b7280',
}

export function Dashboard() {
  const { data: scans, isLoading: scansLoading } = useQuery({
    queryKey: ['scans', { page: 1, per_page: 5 }],
    queryFn: () => scansApi.list({ page: 1, per_page: 5 }),
  })

  const { data: findings, isLoading: findingsLoading } = useQuery({
    queryKey: ['findings', { page: 1, per_page: 100 }],
    queryFn: () => findingsApi.list({ page: 1, per_page: 100 }),
  })

  // Calculate stats with useMemo to prevent recalculation on every render
  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    findings?.data.forEach((f) => {
      counts[f.severity as keyof typeof counts]++
    })
    return counts
  }, [findings?.data])

  const totalFindings = findings?.total || 0
  
  const riskScore = useMemo(() => {
    return Math.min(
      100,
      severityCounts.critical * 25 +
      severityCounts.high * 15 +
      severityCounts.medium * 5 +
      severityCounts.low * 1
    )
  }, [severityCounts])
  
  const riskGrade = useMemo(() => {
    return riskScore >= 80 ? 'F' : riskScore >= 60 ? 'D' : riskScore >= 40 ? 'C' : riskScore >= 20 ? 'B' : 'A'
  }, [riskScore])

  const severityData = useMemo(() => {
    return Object.entries(severityCounts).map(([name, value]) => ({
      name: name.charAt(0).toUpperCase() + name.slice(1),
      value,
    }))
  }, [severityCounts])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Dashboard</h1>
      </div>

      {/* Stats Grid - Responsive */}
      <div className="grid gap-4 grid-cols-2 md:grid-cols-2 lg:grid-cols-5">
        {/* Risk Score */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Risk Score</CardTitle>
          </CardHeader>
          <CardContent>
            {findingsLoading ? (
              <Skeleton className="h-10 w-20" />
            ) : (
              <>
                <div className="text-3xl font-bold text-severity-critical">{riskGrade}</div>
                <p className="text-xs text-muted-foreground">{riskScore}/100</p>
              </>
            )}
          </CardContent>
        </Card>

        {/* Critical */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Critical</CardTitle>
          </CardHeader>
          <CardContent>
            {findingsLoading ? (
              <Skeleton className="h-8 w-12" />
            ) : (
              <div className="text-2xl font-bold text-severity-critical">{severityCounts.critical}</div>
            )}
          </CardContent>
        </Card>

        {/* High */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">High</CardTitle>
          </CardHeader>
          <CardContent>
            {findingsLoading ? (
              <Skeleton className="h-8 w-12" />
            ) : (
              <div className="text-2xl font-bold text-severity-high">{severityCounts.high}</div>
            )}
          </CardContent>
        </Card>

        {/* Medium */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Medium</CardTitle>
          </CardHeader>
          <CardContent>
            {findingsLoading ? (
              <Skeleton className="h-8 w-12" />
            ) : (
              <div className="text-2xl font-bold text-severity-medium">{severityCounts.medium}</div>
            )}
          </CardContent>
        </Card>

        {/* Total Findings */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Total Findings</CardTitle>
          </CardHeader>
          <CardContent>
            {findingsLoading ? (
              <Skeleton className="h-8 w-12" />
            ) : (
              <div className="text-2xl font-bold">{totalFindings}</div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Charts Row */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* Severity Distribution */}
        <Card>
          <CardHeader>
            <CardTitle>Severity Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {findingsLoading ? (
              <Skeleton className="h-64 w-full" />
            ) : (
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={2}
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[entry.name.toLowerCase() as keyof typeof COLORS]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Activity</CardTitle>
          </CardHeader>
          <CardContent>
            {scansLoading ? (
              <div className="space-y-4">
                {[1, 2, 3, 4].map((i) => (
                  <div key={i} className="flex items-center space-x-4">
                    <Skeleton className="h-10 w-10 rounded-full" />
                    <div className="flex-1 space-y-2">
                      <Skeleton className="h-4 w-3/4" />
                      <Skeleton className="h-3 w-1/2" />
                    </div>
                  </div>
                ))}
              </div>
            ) : scans?.items && scans.items.length > 0 ? (
              <div className="space-y-4">
                {scans.items.slice(0, 4).map((scan: ScanList) => {
                  const isCompleted = scan.status === 'completed'
                  const isRunning = scan.status === 'running'
                  const StatusIcon = isCompleted ? CheckCircle : isRunning ? Clock : AlertCircle
                  const statusColor = isCompleted ? 'text-green-500' : isRunning ? 'text-blue-500' : 'text-amber-500'

                  return (
                    <div key={scan.id} className="flex items-center space-x-4">
                      <StatusIcon className={`h-5 w-5 flex-shrink-0 ${statusColor}`} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{scan.name}</p>
                        <p className="text-xs text-muted-foreground">{formatRelativeTime(scan.created_at)}</p>
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : (
              <EmptyState
                icon={Clock}
                title="No recent activity"
                description="Scans will appear here once they run"
              />
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent Scans */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Scans</CardTitle>
        </CardHeader>
        <CardContent>
          {scansLoading ? (
            <Skeleton className="h-32 w-full" />
          ) : (
            <div className="overflow-x-auto">
              <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Profile</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans?.items.map((scan: ScanList) => (
                  <TableRow key={scan.id}>
                    <TableCell className="font-medium">{scan.name}</TableCell>
                    <TableCell>
                      <Badge variant={scan.status === 'completed' ? 'default' : 'secondary'}>
                        {scan.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{scan.profile}</TableCell>
                    <TableCell className="text-muted-foreground">{formatRelativeTime(scan.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
