import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useParams } from '@tanstack/react-router'
import { Download, Save } from 'lucide-react'
import { bugBountyApi } from '@/api/bugbounty'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { SeverityBadge, StatusPill } from '@/components/bugbounty/StatusAtoms'

const nextStates = ['ready_to_send', 'sent', 'acknowledged', 'triaging', 'resolved_paid', 'resolved_dup', 'resolved_na', 'resolved_informative']

export function BBSubmissionDetail() {
  const { submissionId } = useParams({ from: '/bb/submissions/$submissionId' })
  const client = useQueryClient()
  const [title, setTitle] = useState('')
  const [draft, setDraft] = useState('')
  const [transitionTo, setTransitionTo] = useState('ready_to_send')
  const [verdict, setVerdict] = useState<'paid' | 'dup' | 'na' | 'info'>('paid')
  const [payout, setPayout] = useState('')
  const [notes, setNotes] = useState('')
  const [message, setMessage] = useState('')

  const submission = useQuery({ queryKey: ['bb-submission', submissionId], queryFn: () => bugBountyApi.submission(submissionId) })

  useEffect(() => {
    if (submission.data) {
      setTitle(submission.data.title)
      setDraft(submission.data.draft_md || '')
    }
  }, [submission.data])

  const save = useMutation({
    mutationFn: () => bugBountyApi.updateSubmission(submissionId, { title, draft_md: draft }),
    onSuccess: () => {
      setMessage('Draft saved.')
      client.invalidateQueries({ queryKey: ['bb-submission', submissionId] })
    },
  })
  const transition = useMutation({
    mutationFn: () => bugBountyApi.transitionSubmission(submissionId, transitionTo, notes || undefined),
    onSuccess: () => {
      setMessage('State updated.')
      client.invalidateQueries({ queryKey: ['bb-submission', submissionId] })
    },
    onError: (error) => setMessage(String(error)),
  })
  const render = useMutation({
    mutationFn: (format: 'md' | 'docx' | 'pdf') => bugBountyApi.renderSubmission(submissionId, format),
    onSuccess: (result) => setMessage(`Rendered ${result.format}: ${result.path}`),
  })
  const verdictMutation = useMutation({
    mutationFn: () => bugBountyApi.verdictSubmission(submissionId, verdict, payout ? Number(payout) : undefined, notes || undefined),
    onSuccess: () => {
      setMessage('Verdict ingested.')
      client.invalidateQueries({ queryKey: ['bb-submission', submissionId] })
    },
  })

  if (submission.isLoading) {
    return <Skeleton className="h-96 w-full" />
  }

  if (!submission.data) {
    return <p className="text-sm text-muted-foreground">Submission not found.</p>
  }

  const comparableReports = Array.isArray(submission.data.metadata_?.comparable_reports)
    ? (submission.data.metadata_?.comparable_reports as string[])
    : []

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Submission</h1>
        <p className="text-sm text-muted-foreground">Edit the manual platform submission packet.</p>
      </div>

      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 pt-6">
          <SeverityBadge severity={submission.data.severity} />
          <StatusPill>{submission.data.status}</StatusPill>
          <span className="font-mono text-sm">{submission.data.payout_actual || submission.data.payout_expected || 0} {submission.data.currency}</span>
          {message ? <span className="text-sm text-muted-foreground">{message}</span> : null}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-[1fr_420px]">
        <Card>
          <CardHeader>
            <CardTitle>Markdown Draft</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <input value={title} onChange={(event) => setTitle(event.target.value)} className="w-full rounded border border-border bg-surface-2 px-3 py-2 text-sm" />
            <textarea value={draft} onChange={(event) => setDraft(event.target.value)} className="min-h-[520px] w-full rounded border border-border bg-surface-2 p-3 font-mono text-sm" />
            <Button disabled={save.isPending} onClick={() => save.mutate()}>
              <Save className="mr-2 h-4 w-4" />
              Save draft
            </Button>
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Render</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-2">
              {(['md', 'docx', 'pdf'] as const).map((format) => (
                <Button key={format} variant="outline" onClick={() => render.mutate(format)}>
                  <Download className="mr-2 h-4 w-4" />
                  {format}
                </Button>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>State Machine</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <select value={transitionTo} onChange={(event) => setTransitionTo(event.target.value)} className="w-full rounded border border-border bg-surface-2 px-3 py-2 text-sm">
                {nextStates.map((state) => <option key={state} value={state}>{state}</option>)}
              </select>
              <textarea value={notes} onChange={(event) => setNotes(event.target.value)} placeholder="notes" className="h-24 w-full rounded border border-border bg-surface-2 p-3 text-sm" />
              <Button variant="outline" onClick={() => transition.mutate()}>Apply transition</Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Verdict</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <select value={verdict} onChange={(event) => setVerdict(event.target.value as typeof verdict)} className="w-full rounded border border-border bg-surface-2 px-3 py-2 text-sm">
                <option value="paid">paid</option>
                <option value="dup">dup</option>
                <option value="na">N/A</option>
                <option value="info">informative</option>
              </select>
              <input value={payout} onChange={(event) => setPayout(event.target.value)} placeholder="actual payout" className="w-full rounded border border-border bg-surface-2 px-3 py-2 font-mono text-sm" />
              <Button variant="outline" onClick={() => verdictMutation.mutate()}>Ingest verdict</Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Comparable Public Reports</CardTitle>
            </CardHeader>
            <CardContent>
              {comparableReports.length ? (
                <div className="space-y-2 text-sm">
                  {comparableReports.map((item) => (
                    <div key={item} className="rounded border border-border bg-surface-2 p-3 text-muted-foreground">
                      {item}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">No comparable public reports were attached to this draft.</p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
