import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { findingsApi } from '@/api/findings'
import { scansApi } from '@/api/scans'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { FindingsTable } from '@/components/findings/FindingsTable'
import type { FindingSearch } from '@/utils/findingSearch'

export function FindingsList() {
  const search = useSearch({ from: '/findings' }) as FindingSearch
  const navigate = useNavigate({ from: '/findings' })
  const scanId = search.scan_id

  const { data: scan } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId as string),
    enabled: !!scanId,
  })
  const { data: summary } = useQuery({
    queryKey: ['findings-summary', scanId],
    queryFn: () => findingsApi.summary(scanId as string),
    enabled: !!scanId,
  })

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Findings</h1>
        {scanId ? (
          <p className="text-sm text-muted-foreground">
            Showing findings from scan{' '}
            <Link to="/scans/$scanId" params={{ scanId }} className="text-accent underline">
              {scan?.name ?? scanId.slice(0, 8)}
            </Link>{' '}
            only.{' '}
            <Link to="/findings" search={{}} className="underline">Show all scans</Link>
          </p>
        ) : (
          <p className="text-sm text-muted-foreground">
            All scans. Open a scan to see only its findings, or filter below.
          </p>
        )}
      </div>

      {summary && (
        <p className="text-sm text-muted-foreground">
          {summary.total} stored findings: {summary.actionable} low or higher,{' '}
          {summary.informational} informational. Severities are the tools' own.
        </p>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{scanId ? 'Scan findings' : 'All findings'}</CardTitle>
        </CardHeader>
        <CardContent>
          <FindingsTable
            filters={search}
            tools={summary ? Object.keys(summary.by_tool) : ['nuclei', 'nikto', 'http_analysis', 'passive_posture', 'sqlmap', 'dalfox']}
            onChange={(next) => navigate({ search: next })}
          />
        </CardContent>
      </Card>
    </div>
  )
}
