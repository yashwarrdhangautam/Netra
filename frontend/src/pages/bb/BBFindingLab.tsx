import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from '@tanstack/react-router'
import { Upload, Play, FileText } from 'lucide-react'
import { bugBountyApi } from '@/api/bugbounty'
import { findingsApi } from '@/api/findings'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { SeverityBadge, StatusPill } from '@/components/bugbounty/StatusAtoms'
import { formatRelativeTime } from '@/utils/formatters'

export function BBFindingLab() {
  const { findingId } = useParams({ from: '/bb/findings/$findingId' })
  const client = useQueryClient()
  const [selectedEvidence, setSelectedEvidence] = useState('')
  const [verifierId, setVerifierId] = useState('generic_read_only_replay')
  const [confirm, setConfirm] = useState('')
  const [includePoc, setIncludePoc] = useState(true)

  const finding = useQuery({ queryKey: ['finding', findingId], queryFn: () => findingsApi.get(findingId) })
  const evidence = useQuery({ queryKey: ['bb-evidence', findingId], queryFn: () => bugBountyApi.evidence(findingId) })
  const similarReports = useQuery({
    queryKey: ['bb-finding-corpus-context', findingId],
    queryFn: () => bugBountyApi.findingCorpusContext(findingId),
  })
  const verifiers = useQuery({ queryKey: ['bb-verifiers'], queryFn: bugBountyApi.verifiers })
  const upload = useMutation({
    mutationFn: (file: File) => bugBountyApi.uploadEvidence(findingId, file),
    onSuccess: (item) => {
      setSelectedEvidence(item.id)
      client.invalidateQueries({ queryKey: ['bb-evidence', findingId] })
    },
  })
  const replay = useMutation({
    mutationFn: () => bugBountyApi.replayEvidence(selectedEvidence, verifierId, confirm),
  })
  const draft = useMutation({
    mutationFn: () => bugBountyApi.createSubmission(findingId, false, includePoc),
  })

  const chosenVerifier = verifiers.data?.find((item) => item.id === verifierId)
  const vulnClass = String(finding.data?.tags?.[0] || finding.data?.cwe_id || finding.data?.title || '').toLowerCase()

  useEffect(() => {
    if (!verifiers.data?.length) return
    const preferred =
      vulnClass === 'xss'
        ? 'xss_reflected_passive'
        : vulnClass === 'ssrf'
          ? 'ssrf_head_probe'
          : vulnClass === 'idor'
            ? 'idor_read_only'
            : vulnClass === 'sqli'
              ? 'sqli_time_read_only'
              : 'generic_read_only_replay'
    if (verifiers.data.some((item) => item.id === preferred)) {
      setVerifierId(preferred)
    }
  }, [verifiers.data, vulnClass])

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">PoC Lab</h1>
        <p className="text-sm text-muted-foreground">Inspect redacted evidence and replay only through allowlisted verifiers.</p>
      </div>

      {finding.isLoading ? (
        <Skeleton className="h-24 w-full" />
      ) : finding.data ? (
        <Card>
          <CardContent className="flex flex-wrap items-center gap-3 pt-6">
            <SeverityBadge severity={finding.data.severity} cvss={finding.data.cvss_score} />
            <span className="font-medium">{finding.data.title}</span>
            <span className="font-mono text-xs text-muted-foreground">{finding.data.url || 'no url'}</span>
            <StatusPill>{finding.data.status}</StatusPill>
          </CardContent>
        </Card>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[1fr_420px]">
        <Card>
          <CardHeader>
            <CardTitle>Evidence</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <label className="inline-flex cursor-pointer items-center gap-2 rounded border border-border bg-surface-2 px-3 py-2 text-sm hover:bg-surface-3">
              <Upload className="h-4 w-4" />
              Upload evidence
              <input
                type="file"
                className="hidden"
                onChange={(event) => {
                  const file = event.target.files?.[0]
                  if (file) upload.mutate(file)
                }}
              />
            </label>

            {evidence.isLoading ? (
              <Skeleton className="h-40 w-full" />
            ) : (
              <div className="space-y-2">
                {evidence.data?.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => setSelectedEvidence(item.id)}
                    className={`w-full rounded border p-3 text-left text-sm ${selectedEvidence === item.id ? 'border-accent bg-surface-3' : 'border-border bg-surface-2'}`}
                  >
                    <div className="flex items-center gap-2">
                      <FileText className="h-4 w-4" />
                      <span className="font-medium">{item.filename}</span>
                      <span className="ml-auto font-mono text-xs">{item.size_bytes}b</span>
                    </div>
                    <div className="mt-2 flex gap-3 text-xs text-muted-foreground">
                      <span>{item.mime_type}</span>
                      <span>{item.redaction_count} redactions</span>
                      <span>{formatRelativeTime(item.created_at)}</span>
                    </div>
                  </button>
                ))}
                {!evidence.data?.length ? <p className="text-sm text-muted-foreground">No evidence yet. Upload JSON, HTTP transcript, or text output.</p> : null}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Verifier</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <select value={verifierId} onChange={(event) => setVerifierId(event.target.value)} className="w-full rounded border border-border bg-surface-2 px-3 py-2 text-sm">
              {verifiers.data?.map((item) => <option key={item.id} value={item.id}>{item.id}</option>)}
            </select>
            {chosenVerifier ? (
              <div className="rounded border border-border bg-surface-2 p-3 text-sm">
                <p>{chosenVerifier.description}</p>
                <p className="mt-2 text-xs font-medium text-green-300">Will do</p>
                <ul className="mt-1 list-disc pl-4 text-xs text-muted-foreground">
                  {chosenVerifier.will_do.map((line) => <li key={line}>{line}</li>)}
                </ul>
                <p className="mt-2 text-xs font-medium text-red-300">Will not do</p>
                <ul className="mt-1 list-disc pl-4 text-xs text-muted-foreground">
                  {chosenVerifier.will_not_do.map((line) => <li key={line}>{line}</li>)}
                </ul>
              </div>
            ) : null}
            <input value={confirm} onChange={(event) => setConfirm(event.target.value)} placeholder="type program handle to confirm" className="w-full rounded border border-border bg-surface-2 px-3 py-2 font-mono text-sm" />
            <Button disabled={!selectedEvidence || !confirm || replay.isPending} onClick={() => replay.mutate()}>
              <Play className="mr-2 h-4 w-4" />
              Replay
            </Button>
            {replay.data ? (
              <pre className="max-h-80 overflow-auto rounded border border-border bg-surface-2 p-3 font-mono text-xs text-muted-foreground">
                {JSON.stringify(replay.data, null, 2)}
              </pre>
            ) : null}
            {replay.error ? <p className="text-sm text-red-300">Replay failed: {String(replay.error)}</p> : null}
            <label className="flex items-center gap-2 rounded border border-border bg-surface-2 px-3 py-2 text-sm">
              <input type="checkbox" checked={includePoc} onChange={(event) => setIncludePoc(event.target.checked)} />
              Include generated PoC in draft
            </label>
            <Button variant="outline" disabled={!evidence.data?.length || draft.isPending} onClick={() => draft.mutate()}>
              Promote to draft
            </Button>
            {draft.data ? (
              <Link to="/bb/submissions/$submissionId" params={{ submissionId: draft.data.id }}>
                <span className="block text-sm text-accent">Open submission draft</span>
              </Link>
            ) : null}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Comparable Public Reports</CardTitle>
        </CardHeader>
        <CardContent>
          {similarReports.isLoading ? (
            <Skeleton className="h-32 w-full" />
          ) : similarReports.data?.similar_reports.length ? (
            <div className="space-y-2">
              {similarReports.data.similar_reports.map((item) => (
                <div key={item} className="rounded border border-border bg-surface-2 p-3 text-sm text-muted-foreground">
                  {item}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No comparable public prior art found for this finding yet.</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
