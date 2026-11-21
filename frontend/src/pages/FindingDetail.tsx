import { useState } from 'react';
import { Link, useParams, useSearch } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft,
  ArrowUpRight,
  Copy,
  Download,
  Flag,
  MessageSquare,
  AlertCircle,
  ChevronDown,
  Calendar,
} from 'lucide-react';

import { findingsApi } from '@/api/findings';
import apiClient from '@/api/client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { SeverityBadge } from '@/components/findings/SeverityBadge';
import { AIAnalysisPanel } from '@/components/findings/AIAnalysisPanel';
import { LoadingSkeleton } from '@/components/shared/LoadingSkeleton';
import { EmptyState } from '@/components/shared/EmptyState';
import { CopyCurlButton } from '@/components/findings/CopyCurlButton';
import { cn } from '@/utils/formatters';
import { STATUS_LABELS } from '@/utils/findingStatus';
import { safeHref } from '@/utils/safeHref';
import type { FindingSearch } from '@/utils/findingSearch';
import type { Finding } from '@/types/findings';

type TabType = 'details' | 'evidence' | 'remediation' | 'ai_analysis' | 'history';

const TAB_LABELS: Record<TabType, string> = {
  details: 'Details',
  evidence: 'Evidence',
  remediation: 'Remediation',
  ai_analysis: 'AI analysis',
  history: 'History',
};

const STATUS_COLORS: Record<string, string> = {
  new: 'bg-blue-500/20 text-blue-300',
  needs_review: 'bg-amber-500/20 text-amber-300',
  confirmed: 'bg-yellow-500/20 text-yellow-300',
  in_progress: 'bg-purple-500/20 text-purple-300',
  resolved: 'bg-green-500/20 text-green-300',
  verified: 'bg-green-500/20 text-green-300',
  false_positive: 'bg-gray-500/20 text-gray-300',
  accepted_risk: 'bg-gray-500/20 text-gray-300',
};

// Evidence keys that carry raw HTTP exchanges in nuclei/nikto output.
const RAW_KEYS = ['request', 'response', 'curl-command', 'matched-at', 'extracted-results', 'matcher-name'];

interface HistoryEntry {
  at: string | null;
  actor: string | null;
  action: string;
  changes: Record<string, [string | null, string | null]>;
}


function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs uppercase text-surface-10">{label}</dt>
      <dd className="break-words text-sm text-surface-12">{value ?? <span className="text-surface-9">Not available</span>}</dd>
    </div>
  );
}

export function FindingDetail() {
  const { findingId } = useParams({ from: '/findings/$findingId' });
  const search = useSearch({ from: '/findings/$findingId' }) as FindingSearch;
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('details');
  const [showStatusMenu, setShowStatusMenu] = useState(false);
  const [showNoteInput, setShowNoteInput] = useState(false);
  const [note, setNote] = useState('');

  const { data: finding, isLoading, error } = useQuery({
    queryKey: ['finding', findingId],
    queryFn: () => findingsApi.get(findingId),
  });
  const { data: history = [] } = useQuery({
    queryKey: ['finding-history', findingId],
    queryFn: async () =>
      (await apiClient.get<HistoryEntry[]>(`/api/v1/findings/${findingId}/history`)).data,
    enabled: activeTab === 'history',
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['finding', findingId] });
    queryClient.invalidateQueries({ queryKey: ['finding-history', findingId] });
    queryClient.invalidateQueries({ queryKey: ['findings'] });
    queryClient.invalidateQueries({ queryKey: ['findings-summary'] });
  };
  const updateMutation = useMutation({
    mutationFn: (payload: Partial<Finding>) => findingsApi.update(findingId, payload),
    onSuccess: () => {
      invalidate();
      setShowStatusMenu(false);
    },
  });
  const falsePositiveMutation = useMutation({
    mutationFn: () => findingsApi.markFalsePositive(findingId),
    onSuccess: invalidate,
  });

  if (isLoading) return <LoadingSkeleton />;
  if (error || !finding) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Finding not found"
        description="The finding you're looking for doesn't exist or has been deleted."
      />
    );
  }

  const scanId = search.scan_id ?? finding.scan_id;
  const href = safeHref(finding.url);
  const evidence = (finding.evidence ?? {}) as Record<string, unknown>;
  const raw = RAW_KEYS.filter((k) => evidence[k] != null);
  const knowledge = finding.knowledge ?? [];
  const copy = (text: string) => navigator.clipboard.writeText(text);

  const saveNote = () => {
    const text = note.trim();
    if (!text) return;
    updateMutation.mutate({ notes: `\n[${new Date().toISOString()}] ${text}` } as Partial<Finding>, {
      onSuccess: () => {
        setNote('');
        setShowNoteInput(false);
      },
    });
  };

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(finding, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `netra-finding-${finding.id.slice(0, 8)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <Link to="/findings" search={{ scan_id: scanId }} className="inline-flex items-center gap-1 text-sm text-accent hover:underline">
        <ArrowLeft className="h-4 w-4" /> Back to {finding.scan_name ? `findings of “${finding.scan_name}”` : 'scan findings'}
      </Link>

      <div className="space-y-4">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-3">
              <SeverityBadge severity={finding.severity} />
              <h1 className="text-2xl font-bold text-surface-12">{finding.title}</h1>
            </div>
            {finding.description && finding.description !== finding.title && (
              <p className="text-surface-11">{finding.description}</p>
            )}
          </div>

          <div className="relative">
            <Button variant="outline" className="flex items-center gap-2" onClick={() => setShowStatusMenu(!showStatusMenu)}>
              <Badge className={cn('', STATUS_COLORS[finding.status as string])}>
                {STATUS_LABELS[finding.status as string] ?? finding.status}
              </Badge>
              <ChevronDown className="h-4 w-4" />
            </Button>
            {showStatusMenu && (
              <div className="absolute right-0 top-12 z-50 w-52 rounded-lg border border-surface-6 bg-surface-1 shadow-lg">
                {Object.entries(STATUS_LABELS).map(([status, label]) => (
                  <button key={status} type="button"
                    onClick={() => updateMutation.mutate({ status: status as Finding['status'] })}
                    className={cn('w-full px-4 py-2 text-left text-sm transition-colors first:rounded-t-lg last:rounded-b-lg hover:bg-surface-3', finding.status === status && 'bg-surface-2')}
                    disabled={updateMutation.isPending}>
                    {label}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="flex flex-wrap gap-6 text-sm text-surface-11">
          <span className="flex items-center gap-2">
            <Calendar className="h-4 w-4" /> Detected {new Date(finding.created_at).toLocaleString()}
          </span>
          {finding.url && (href ? (
            <a href={href} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-blue-400 hover:text-blue-300">
              <ArrowUpRight className="h-4 w-4" /> {finding.url}
            </a>
          ) : <span className="break-all">{finding.url}</span>)}
        </div>
        {updateMutation.isError && <p className="text-sm text-red-400">The change could not be saved.</p>}
      </div>

      <div className="flex flex-wrap gap-3">
        <Button variant="secondary" size="sm" className="flex items-center gap-2"
          disabled={falsePositiveMutation.isPending || finding.status === 'false_positive'}
          onClick={() => { if (confirm('Mark this finding as a false positive?')) falsePositiveMutation.mutate(); }}>
          <Flag className="h-4 w-4" /> Mark false positive
        </Button>
        <Button variant="secondary" size="sm" className="flex items-center gap-2" onClick={() => setShowNoteInput(!showNoteInput)}>
          <MessageSquare className="h-4 w-4" /> Add note
        </Button>
        <CopyCurlButton findingId={finding.id} variant="outline" size="sm" />
        <Button variant="outline" size="sm" className="flex items-center gap-2" onClick={exportJson}>
          <Download className="h-4 w-4" /> Export JSON
        </Button>
      </div>

      {showNoteInput && (
        <Card className="border-surface-6 bg-surface-2">
          <CardContent className="space-y-3 pt-6">
            <textarea aria-label="Note" value={note} onChange={(e) => setNote(e.target.value)}
              placeholder="Add a note about this finding..."
              className="h-24 w-full rounded-lg border border-surface-6 bg-surface-1 px-3 py-2 text-surface-12 placeholder-surface-9 focus:border-blue-500 focus:outline-none" />
            <div className="flex gap-2">
              <Button size="sm" onClick={saveNote} disabled={!note.trim() || updateMutation.isPending}>Save note</Button>
              <Button variant="outline" size="sm" onClick={() => setShowNoteInput(false)}>Cancel</Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="space-y-4">
        <div className="flex border-b border-surface-6">
          {(Object.keys(TAB_LABELS) as TabType[]).map((tab) => (
            <button key={tab} type="button" onClick={() => setActiveTab(tab)}
              className={cn('px-4 py-2 text-sm font-medium transition-colors', activeTab === tab ? 'border-b-2 border-blue-500 text-blue-400' : 'text-surface-11 hover:text-surface-12')}>
              {TAB_LABELS[tab]}
            </button>
          ))}
        </div>

        {activeTab === 'details' && (
          <div className="space-y-4">
            <Card className="border-surface-6 bg-surface-1">
              <CardHeader><CardTitle>Identification</CardTitle></CardHeader>
              <CardContent>
                <dl className="grid gap-4 md:grid-cols-3">
                  <Field label="Finding ID" value={<span className="font-mono text-xs">{finding.id}</span>} />
                  <Field label="Scan" value={<Link to="/scans/$scanId" params={{ scanId: finding.scan_id }} className="text-accent hover:underline">{finding.scan_name ?? finding.scan_id}</Link>} />
                  <Field label="Target" value={finding.target} />
                  <Field label="Affected URL" value={finding.url} />
                  <Field label="Parameter" value={finding.parameter} />
                  <Field label="Detection tool" value={finding.tool_source} />
                  <Field label="Check / template ID" value={finding.check_id} />
                  <Field label="Category" value={knowledge[0]?.category} />
                  <Field label="CWE" value={finding.cwe_id ?? knowledge[0]?.cwe} />
                  <Field label="CVE" value={finding.cve_ids?.length ? finding.cve_ids.join(', ') : 'None (no CVE applies)'} />
                  <Field label="CVSS" value={finding.cvss_score != null ? `${finding.cvss_score}${finding.cvss_vector ? ` (${finding.cvss_vector})` : ''}` : undefined} />
                  <Field label="Confidence" value={finding.confidence != null ? `${finding.confidence}%` : undefined} />
                </dl>
                <p className="mt-3 text-xs text-surface-10">Severity is the detection tool's own rating; NETRA does not raise it.</p>
              </CardContent>
            </Card>

            {knowledge.length === 0 ? (
              <Card className="border-surface-6 bg-surface-1">
                <CardContent className="pt-6 text-sm text-surface-10">
                  No reviewed explanation is available for this check yet. Use the Evidence tab and the tool's
                  documentation for this check ID, and verify the result manually.
                </CardContent>
              </Card>
            ) : knowledge.map((k) => (
              <Card key={k.key} className="border-surface-6 bg-surface-1">
                <CardHeader><CardTitle>{k.title}</CardTitle></CardHeader>
                <CardContent>
                  <dl className="space-y-3">
                    <Field label="What it is" value={k.purpose} />
                    <Field label="Security impact" value={k.impact} />
                    <Field label="Exploitation conditions" value={k.conditions} />
                    <Field label="False-positive considerations" value={k.false_positive} />
                    <Field label="Mapping" value={[...k.owasp, ...(k.cwe ? [k.cwe] : [])].join(' · ') || 'No accurate OWASP/CWE mapping'} />
                  </dl>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {activeTab === 'evidence' && (
          <Card className="border-surface-6 bg-surface-1">
            <CardHeader><CardTitle>Evidence</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              {raw.map((key) => {
                const value = typeof evidence[key] === 'string' ? (evidence[key] as string) : JSON.stringify(evidence[key], null, 2);
                return (
                  <div key={key} className="space-y-1">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-semibold text-surface-12">{key}</h3>
                      <button type="button" onClick={() => copy(value)} className="text-surface-10 hover:text-surface-11" title="Copy"><Copy className="h-4 w-4" /></button>
                    </div>
                    <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-lg bg-surface-2 p-3 font-mono text-xs text-surface-11">{value}</pre>
                  </div>
                );
              })}
              {Object.keys(evidence).length > 0 ? (
                <div className="space-y-1">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-surface-12">Raw tool evidence</h3>
                    <button type="button" onClick={() => copy(JSON.stringify(evidence, null, 2))} className="text-surface-10 hover:text-surface-11" title="Copy"><Copy className="h-4 w-4" /></button>
                  </div>
                  <pre className="max-h-[32rem] overflow-auto whitespace-pre-wrap rounded-lg bg-surface-2 p-3 font-mono text-xs text-surface-11">{JSON.stringify(evidence, null, 2)}</pre>
                </div>
              ) : (
                <p className="text-surface-10">The tool recorded no evidence for this finding.</p>
              )}
            </CardContent>
          </Card>
        )}

        {activeTab === 'remediation' && (
          <Card className="border-surface-6 bg-surface-1">
            <CardHeader><CardTitle>Remediation</CardTitle></CardHeader>
            <CardContent className="space-y-4 text-sm">
              {finding.remediation && <Field label="From the finding" value={finding.remediation} />}
              {knowledge.map((k) => (
                <div key={k.key} className="space-y-2">
                  <Field label={k.title} value={k.remediation} />
                  <Field label="Retest" value={<code className="font-mono text-xs">{k.retest}</code>} />
                  {k.references.length > 0 && (
                    <Field label="References" value={
                      <ul>{k.references.map((r) => <li key={r}><a href={safeHref(r) ?? undefined} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">{r}</a></li>)}</ul>
                    } />
                  )}
                </div>
              ))}
              {finding.ai_analysis?.defender?.fix_summary && <Field label="AI suggestion (unverified)" value={finding.ai_analysis.defender.fix_summary} />}
              {!finding.remediation && knowledge.length === 0 && !finding.ai_analysis?.defender && (
                <p className="text-surface-10">No remediation guidance is available for this check.</p>
              )}
            </CardContent>
          </Card>
        )}

        {activeTab === 'ai_analysis' && (finding.ai_analysis && Object.keys(finding.ai_analysis).length > 0
          ? <AIAnalysisPanel analysis={finding.ai_analysis} />
          : <p className="text-sm text-surface-10">No AI analysis was run for this finding.</p>)}

        {activeTab === 'history' && (
          <Card className="border-surface-6 bg-surface-1">
            <CardHeader><CardTitle>History</CardTitle></CardHeader>
            <CardContent>
              <ol className="space-y-3 text-sm">
                <li><span className="font-medium">Detected</span> by {finding.tool_source} · {new Date(finding.created_at).toLocaleString()}</li>
                {history.map((h, i) => (
                  <li key={i}>
                    <span className="font-medium">{h.action}</span> by {h.actor ?? 'unknown'} · {h.at ? new Date(h.at).toLocaleString() : ''}
                    {Object.entries(h.changes).map(([field, [from, to]]) => (
                      <span key={field} className="block text-surface-10">{field}: {String(from)} → {String(to)}</span>
                    ))}
                  </li>
                ))}
              </ol>
              {finding.notes && <pre className="mt-4 whitespace-pre-wrap rounded bg-surface-2 p-3 text-xs">{finding.notes}</pre>}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
