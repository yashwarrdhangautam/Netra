import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ScanDetail } from './ScanDetail'

type Coverage = { phase: string; tool: string; state: string; required: boolean; reason_code: string }
type Run = { tool: string; target: string; state: string; status: string; reason?: string | null; error?: string | null }
type Phase = {
  id: string
  phase_type: string
  status: string
  outcome?: string
  findings_count: number
  stored_findings?: number
  started_at: string | null
  completed_at: string | null
  error_message?: string | null
  runs?: Run[]
}

const data = vi.hoisted(() => ({
  scan: {
    name: 'Legacy',
    status: 'completed',
    profile: 'quick',
    outcome: 'incomplete',
    coverage_reason: 'coverage_unknown',
    coverage: [] as Coverage[],
  },
  phases: [] as Phase[],
  summary: {
    scan_id: 'test',
    total: 34,
    by_severity: { critical: 0, high: 0, medium: 0, low: 5, info: 29 },
    by_tool: { nikto: 18, nuclei: 7 },
    by_status: { new: 34 },
    informational: 29,
    actionable: 5,
    unique: 34,
    verified: 0,
    false_positive: 0,
  },
  mutate: vi.fn(),
}))

vi.mock('@tanstack/react-router', () => ({
  useParams: () => ({ scanId: 'test' }),
  Link: ({ children }: { children: unknown }) => children,
}))
vi.mock('@/components/findings/FindingsTable', () => ({
  FindingsTable: ({ filters }: { filters: { scan_id?: string } }) => <div>findings-table:{filters.scan_id}</div>,
}))
vi.mock('@tanstack/react-query', () => ({
  useQuery: ({ queryKey }: { queryKey: string[] }) => ({
    data:
      queryKey[0] === 'scan-phases'
        ? data.phases
        : queryKey[0] === 'findings-summary'
          ? data.summary
          : queryKey[0] === 'scan'
            ? data.scan
            : undefined,
    isLoading: false,
  }),
  useMutation: () => ({ mutate: data.mutate, isPending: false, isError: false }),
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
}))

describe('ScanDetail', () => {
  afterEach(() => cleanup())
  beforeEach(() => {
    data.scan.status = 'completed'
    data.scan.coverage = []
    data.phases = []
    data.mutate.mockReset()
  })

  it('shows stored finding counts that reconcile with the summary', () => {
    render(<ScanDetail />)
    expect(screen.getByText('34')).toBeTruthy()
    expect(screen.getByText(/5 low or higher · 29 informational/)).toBeTruthy()
    expect(screen.getByText(/View all 34 findings/)).toBeTruthy()
  })

  it('opens the findings tab scoped to this scan', () => {
    render(<ScanDetail />)
    fireEvent.click(screen.getByText(/View all 34 findings/))
    expect(screen.getByText('findings-table:test')).toBeTruthy()
  })

  it('shows incomplete coverage separately from completed lifecycle', () => {
    render(<ScanDetail />)
    fireEvent.click(screen.getByRole('tab', { name: 'Coverage & limitations' }))
    expect(screen.getByText('Incomplete coverage')).toBeTruthy()
    expect(screen.getByText(/Coverage evidence is unavailable/)).toBeTruthy()
  })

  it('shows missing required tool reason', () => {
    data.scan.coverage = [
      { phase: 'scope', tool: 'recontool', state: 'unavailable', required: true, reason_code: 'run_missing' },
    ]
    render(<ScanDetail />)
    fireEvent.click(screen.getByRole('tab', { name: 'Coverage & limitations' }))
    expect(screen.getByText(/recontool/)).toBeTruthy()
    expect(screen.getByText(/run_missing/)).toBeTruthy()
  })

  it('has no stop buttons on a finished scan', () => {
    render(<ScanDetail />)
    expect(screen.queryByText('Cancel scan')).toBeNull()
  })

  it('cancels a running scan only after confirmation', () => {
    data.scan.status = 'running'
    render(<ScanDetail />)
    fireEvent.click(screen.getByText('Cancel scan'))
    expect(data.mutate).not.toHaveBeenCalled()
    fireEvent.click(screen.getByText('Yes, cancel'))
    expect(data.mutate).toHaveBeenCalledWith('cancelled')
  })

  it('lists phases with skip reasons and tool runs that timed out or failed', () => {
    data.phases = [
      {
        id: 'p1',
        phase_type: 'pentest',
        status: 'skipped',
        outcome: 'skipped',
        findings_count: 0,
        started_at: '2026-11-21T04:00:00Z',
        completed_at: '2026-11-21T04:00:01Z',
        error_message: 'active_test_not_authorized',
      },
      {
        id: 'p2',
        phase_type: 'vuln_scan',
        status: 'completed',
        outcome: 'completed_with_warnings',
        findings_count: 25,
        stored_findings: 25,
        started_at: '2026-11-21T09:39:57Z',
        completed_at: '2026-11-21T14:46:49Z',
        runs: [
          { tool: 'nuclei', target: 'http://x:80', state: 'failed', status: 'timed_out', reason: 'Timed out: stopped at its time budget' },
        ],
      },
    ]
    render(<ScanDetail />)
    fireEvent.click(screen.getByRole('tab', { name: /Tool execution/ }))
    expect(screen.getByText('Active testing')).toBeTruthy()
    expect(screen.getByText(/active_test_not_authorized/)).toBeTruthy()
    // The header pill and the vuln phase both show it; plain green "completed" would be wrong.
    expect(screen.getAllByText('completed with warnings').length).toBe(2)
    expect(screen.getByText('timed out')).toBeTruthy()
  })
})
