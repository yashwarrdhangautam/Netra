import { Link } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { findingsApi } from '@/api/findings'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table'
import { Button } from '@/components/ui/Button'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import { cn } from '@/utils/formatters'
import { toFindingFilters, type FindingSearch } from '@/utils/findingSearch'
import { STATUS_LABELS } from '@/utils/findingStatus'

const PER_PAGE = 50
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

const INPUT = 'rounded-md border border-border bg-surface-2 px-2 py-1.5 text-sm text-foreground'

interface Props {
  filters: FindingSearch
  onChange: (next: FindingSearch) => void
  /** Tools to offer in the tool filter (from the scan summary). */
  tools?: string[]
}

/** Filterable, paginated findings table. Every row opens the finding with the scan kept in the URL. */
export function FindingsTable({ filters, onChange, tools = [] }: Props) {
  const page = filters.page ?? 1
  const { data, isLoading, isError } = useQuery({
    queryKey: ['findings', filters],
    queryFn: () => findingsApi.list({ ...toFindingFilters(filters), page, per_page: PER_PAGE }),
  })
  const set = (patch: Partial<FindingSearch>) => onChange({ ...filters, ...patch, page: undefined })
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / PER_PAGE))

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-xs text-muted-foreground">
          Severity
          <select aria-label="Severity" className={cn(INPUT, 'block')} value={filters.severity ?? ''}
            onChange={(e) => set({ severity: e.target.value || undefined })}>
            <option value="">All</option>
            <option value="critical,high,medium,low">Low and above (actionable)</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label className="text-xs text-muted-foreground">
          Tool
          <select aria-label="Tool" className={cn(INPUT, 'block')} value={filters.tool_source ?? ''}
            onChange={(e) => set({ tool_source: e.target.value || undefined })}>
            <option value="">All</option>
            {tools.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <label className="text-xs text-muted-foreground">
          Status
          <select aria-label="Status" className={cn(INPUT, 'block')} value={filters.status ?? ''}
            onChange={(e) => set({ status: e.target.value || undefined })}>
            <option value="">All</option>
            {Object.entries(STATUS_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <label className="text-xs text-muted-foreground">
          CWE
          <input aria-label="CWE" className={cn(INPUT, 'block w-28')} placeholder="CWE-693"
            defaultValue={filters.cwe_id ?? ''}
            onBlur={(e) => set({ cwe_id: e.target.value.trim() || undefined })} />
        </label>
        <label className="min-w-48 flex-1 text-xs text-muted-foreground">
          Search title or URL
          <input aria-label="Search" className={cn(INPUT, 'block w-full')} defaultValue={filters.q ?? ''}
            onKeyDown={(e) => { if (e.key === 'Enter') set({ q: e.currentTarget.value.trim() || undefined }) }}
            onBlur={(e) => set({ q: e.target.value.trim() || undefined })} />
        </label>
      </div>

      {isError && <p className="text-sm text-red-400">Findings could not be loaded. Check the filters and try again.</p>}
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : (data?.items.length ?? 0) === 0 ? (
        <p className="text-sm text-muted-foreground">No findings match these filters.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Severity</TableHead>
              <TableHead>Title</TableHead>
              <TableHead>Affected</TableHead>
              <TableHead>Tool</TableHead>
              <TableHead>CWE</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data?.items.map((f) => (
              <TableRow key={f.id}>
                <TableCell><SeverityBadge severity={f.severity} /></TableCell>
                <TableCell className="font-medium">
                  <Link to="/findings/$findingId" params={{ findingId: f.id }}
                    search={{ scan_id: filters.scan_id ?? f.scan_id }}
                    className="text-accent hover:underline">
                    {f.title}
                  </Link>
                </TableCell>
                <TableCell className="max-w-64 truncate text-xs text-muted-foreground">
                  {f.url ?? '—'}
                </TableCell>
                <TableCell className="text-muted-foreground">{f.tool_source}</TableCell>
                <TableCell className="text-muted-foreground">{f.cwe_id ?? '—'}</TableCell>
                <TableCell>{STATUS_LABELS[f.status] ?? f.status}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <span>{data?.total ?? 0} findings</span>
        {pages > 1 && (
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" disabled={page <= 1}
              onClick={() => onChange({ ...filters, page: page - 1 })}>Previous</Button>
            <span>Page {page} of {pages}</span>
            <Button size="sm" variant="outline" disabled={page >= pages}
              onClick={() => onChange({ ...filters, page: page + 1 })}>Next</Button>
          </div>
        )}
      </div>
    </div>
  )
}
