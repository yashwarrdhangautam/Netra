import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { bugBountyApi } from '@/api/bugbounty'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { SeverityBadge, StatusPill } from '@/components/bugbounty/StatusAtoms'
import { formatRelativeTime } from '@/utils/formatters'

export function BBSubmissions() {
  const [programId, setProgramId] = useState('')
  const programs = useQuery({ queryKey: ['bb-programs'], queryFn: bugBountyApi.programs })
  const submissions = useQuery({
    queryKey: ['bb-submissions', programId],
    queryFn: () => bugBountyApi.submissions(programId || undefined),
  })

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Submission Center</h1>
        <p className="text-sm text-muted-foreground">Drafts, verdicts, and payout tracking.</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Filters</CardTitle>
        </CardHeader>
        <CardContent>
          <select value={programId} onChange={(event) => setProgramId(event.target.value)} className="rounded border border-border bg-surface-2 px-3 py-2 text-sm">
            <option value="">All programs</option>
            {programs.data?.map((program) => <option key={program.id} value={program.id}>{program.platform}/{program.handle}</option>)}
          </select>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Submissions</CardTitle>
        </CardHeader>
        <CardContent>
          {submissions.isLoading ? (
            <Skeleton className="h-48 w-full" />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="py-2">Title</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Payout</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {submissions.data?.map((submission) => (
                    <tr key={submission.id} className="border-t border-border">
                      <td className="py-2">
                        <Link to="/bb/submissions/$submissionId" params={{ submissionId: submission.id }}>
                          <span className="hover:text-accent">{submission.title}</span>
                        </Link>
                      </td>
                      <td><SeverityBadge severity={submission.severity} /></td>
                      <td><StatusPill>{submission.status}</StatusPill></td>
                      <td className="font-mono tabular-nums">{submission.payout_actual || submission.payout_expected || 0} {submission.currency}</td>
                      <td className="text-muted-foreground">{formatRelativeTime(submission.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!submissions.data?.length ? <p className="mt-3 text-sm text-muted-foreground">No submissions yet.</p> : null}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
