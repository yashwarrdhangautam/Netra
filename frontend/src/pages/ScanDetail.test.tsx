import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ScanDetail } from './ScanDetail'

type Coverage = { phase: string; tool: string; state: string; required: boolean; reason_code: string }
type Phase = {
  id: string
  phase_type: string
  status: string
  findings_count: number
  started_at: string | null
  completed_at: string | null
  error_message?: string | null
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
  mutate: vi.fn(),
}))

vi.mock('@tanstack/react-router', () => ({ useParams: () => ({ scanId: 'test' }) }))
vi.mock('@tanstack/react-query', () => ({
  useQuery: ({ queryKey }: { queryKey: string[] }) => ({
    data: queryKey[0] === 'scan-phases' ? data.phases : data.scan,
    isLoading: false,
  }),
  useMutation: () => ({ mutate: data.mutate, isPending: false, isError: false }),
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
}))

describe('ScanDetail coverage', () => {
  beforeEach(() => {
    data.scan.status = 'completed'
    data.phases = []
    data.mutate.mockReset()
  })

  it('shows incomplete coverage separately from completed lifecycle', () => {
    render(<ScanDetail />)
    expect(screen.getByText('Incomplete coverage')).toBeTruthy()
    expect(screen.getByText(/Coverage evidence is unavailable/)).toBeTruthy()
  })

  it('shows missing required tool reason', () => {
    data.scan.coverage = [
      { phase: 'scope', tool: 'recontool', state: 'unavailable', required: true, reason_code: 'run_missing' },
    ]
    render(<ScanDetail />)
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

  it('lists phases with their skip reason', () => {
    data.phases = [
      {
        id: 'p1',
        phase_type: 'pentest',
        status: 'skipped',
        findings_count: 0,
        started_at: '2026-11-21T04:00:00Z',
        completed_at: '2026-11-21T04:00:01Z',
        error_message: 'active_test_not_authorized',
      },
    ]
    render(<ScanDetail />)
    expect(screen.getByText(/pentest/)).toBeTruthy()
    expect(screen.getByText('active_test_not_authorized')).toBeTruthy()
  })
})
