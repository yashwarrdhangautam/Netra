import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { reportsApi, type ReportType } from '@/api/reports'
import { reportFilesApi } from '@/api/platform'
import { scansApi } from '@/api/scans'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { NotificationBanner, type BannerMessage } from '@/components/shared/NotificationBanner'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table'

const reportTypes: { value: ReportType; label: string; description: string }[] = [
  { value: 'executive', label: 'Executive', description: 'Short PDF summary for leadership' },
  { value: 'technical', label: 'Technical', description: 'Detailed Word document' },
  { value: 'pentest', label: 'Pentest', description: 'Pentest deliverable (PDF)' },
  { value: 'html', label: 'HTML', description: 'Interactive, offline-readable report' },
  { value: 'excel', label: 'Excel', description: 'Multi-sheet workbook' },
  { value: 'evidence', label: 'Evidence', description: 'ZIP with SHA256 chain of custody' },
  { value: 'compliance', label: 'Compliance', description: 'Framework gap analysis' },
  { value: 'delta', label: 'Delta', description: 'What changed since the previous scan' },
  { value: 'api', label: 'API security', description: 'API-focused findings' },
  { value: 'cloud', label: 'Cloud', description: 'Cloud posture findings' },
  { value: 'full', label: 'Full', description: 'Everything combined' },
]

interface ReportRow {
  id: string
  scan_id: string
  report_type: string
  status: string
  file_path?: string | null
  file_size?: number | null
  created_at: string
}

function errorText(err: unknown, fallback: string): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

export function Reports() {
  const queryClient = useQueryClient()
  const [scanId, setScanId] = useState('')
  const [selectedType, setSelectedType] = useState<ReportType>('executive')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<BannerMessage | null>(null)

  const { data: scans } = useQuery({
    queryKey: ['scans-for-reports'],
    queryFn: () => scansApi.list({ page: 1, per_page: 100 }),
  })

  const { data: history = [], isLoading } = useQuery({
    queryKey: ['reports-history'],
    queryFn: async () => (await reportFilesApi.list()) as unknown as ReportRow[],
    // Keep polling while a report is still being built.
    refetchInterval: (query) => {
      const rows = (query.state.data ?? []) as ReportRow[]
      return rows.some((r) => r.status === 'generating' || r.status === 'pending') ? 3000 : false
    },
  })

  const scanName = (id: string) => scans?.items.find((s) => s.id === id)?.name ?? id.slice(0, 8)

  const generate = async () => {
    if (!scanId) return setMessage({ type: 'error', text: 'Choose a scan first.' })
    setBusy(true)
    try {
      await reportsApi.generate(scanId, selectedType)
      setMessage({ type: 'success', text: 'Report queued. It appears in the history below when ready.' })
      await queryClient.invalidateQueries({ queryKey: ['reports-history'] })
    } catch (err) {
      setMessage({ type: 'error', text: errorText(err, 'Could not start the report.') })
    } finally {
      setBusy(false)
    }
  }

  const download = async (row: ReportRow) => {
    const ext = row.report_type === 'excel' ? 'xlsx' : row.report_type === 'html' ? 'html' : 'bin'
    try {
      await reportFilesApi.download(row.id, `netra-${row.report_type}-${row.id.slice(0, 8)}.${ext}`)
    } catch (err) {
      setMessage({ type: 'error', text: errorText(err, 'The report file is not available.') })
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Reports</h1>
        <p className="text-sm text-muted-foreground">Generate a report for a scan, then download it here.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Generate</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <label className="block text-sm">
            <span className="mb-1 block text-muted-foreground">Scan</span>
            <select
              aria-label="Scan"
              value={scanId}
              onChange={(e) => setScanId(e.target.value)}
              className="w-full rounded border border-border bg-surface-2 p-2 text-sm"
            >
              <option value="">Choose a scan…</option>
              {scans?.items.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.status})
                </option>
              ))}
            </select>
          </label>

          <div className="grid gap-3 md:grid-cols-3 lg:grid-cols-4">
            {reportTypes.map((type) => (
              <button
                key={type.value}
                type="button"
                aria-pressed={selectedType === type.value}
                onClick={() => setSelectedType(type.value)}
                className={`rounded-md border p-3 text-left transition-colors ${
                  selectedType === type.value ? 'border-accent bg-surface-2' : 'border-border'
                }`}
              >
                <div className="text-sm font-medium text-foreground">{type.label}</div>
                <div className="text-xs text-muted-foreground">{type.description}</div>
              </button>
            ))}
          </div>

          <Button onClick={generate} disabled={busy || !scanId}>
            {busy ? 'Starting…' : 'Generate report'}
          </Button>
          <NotificationBanner message={message} onDismiss={() => setMessage(null)} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>History</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : history.length === 0 ? (
            <p className="text-sm text-muted-foreground">No reports yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Created</TableHead>
                  <TableHead>Scan</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>File</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {history.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell className="text-xs">{new Date(row.created_at).toLocaleString()}</TableCell>
                    <TableCell>{scanName(row.scan_id)}</TableCell>
                    <TableCell>{row.report_type}</TableCell>
                    <TableCell>{row.status}</TableCell>
                    <TableCell>
                      {row.status === 'completed' ? (
                        <Button variant="ghost" size="sm" onClick={() => download(row)}>
                          Download
                        </Button>
                      ) : row.status === 'failed' ? (
                        <span className="text-xs text-red-400">Failed</span>
                      ) : (
                        <span className="text-xs text-muted-foreground">Working…</span>
                      )}
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
