import { useState } from 'react';
import { useParams } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowUpRight,
  CheckCircle,
  Copy,
  Download,
  Flag,
  MessageSquare,
  AlertCircle,
  ChevronDown,
  Calendar,
} from 'lucide-react';

import { findingsApi } from '@/api/findings';
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { SeverityBadge } from '@/components/findings/SeverityBadge';
import { AIAnalysisPanel } from '@/components/findings/AIAnalysisPanel';
import { LoadingSkeleton } from '@/components/shared/LoadingSkeleton';
import { EmptyState } from '@/components/shared/EmptyState';
import { CopyCurlButton } from '@/components/findings/CopyCurlButton';
import { cn } from '@/utils/formatters';
import type { Finding } from '@/types/findings';

type TabType = 'evidence' | 'ai_analysis' | 'remediation' | 'compliance' | 'history';

const STATUS_LABELS: Record<string, string> = {
  new: 'New',
  confirmed: 'Confirmed',
  in_progress: 'In Progress',
  resolved: 'Resolved',
  false_positive: 'False Positive',
};

const STATUS_COLORS: Record<string, string> = {
  new: 'bg-blue-500/20 text-blue-300',
  confirmed: 'bg-yellow-500/20 text-yellow-300',
  in_progress: 'bg-purple-500/20 text-purple-300',
  resolved: 'bg-green-500/20 text-green-300',
  false_positive: 'bg-gray-500/20 text-gray-300',
};

export function FindingDetail() {
  const { findingId } = useParams({ from: '/findings/$findingId' });
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('evidence');
  const [showStatusMenu, setShowStatusMenu] = useState(false);
  const [showNoteInput, setShowNoteInput] = useState(false);

  const { data: finding, isLoading, error } = useQuery({
    queryKey: ['finding', findingId],
    queryFn: () => findingsApi.get(findingId),
  });

  const updateMutation = useMutation({
    mutationFn: (payload: Partial<Finding>) =>
      findingsApi.update(findingId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', findingId] });
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      setShowStatusMenu(false);
    },
  });

  const falsPositiveMutation = useMutation({
    mutationFn: () => findingsApi.markFalsePositive(findingId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', findingId] });
      queryClient.invalidateQueries({ queryKey: ['findings'] });
    },
  });

  const handleStatusChange = (status: string) => {
    updateMutation.mutate({ status: status as any });
  };

  const handleMarkFalsePositive = () => {
    if (
      confirm(
        'Are you sure you want to mark this finding as a false positive?'
      )
    ) {
      falsPositiveMutation.mutate();
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  if (isLoading) {
    return <LoadingSkeleton />;
  }

  if (error || !finding) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Finding not found"
        description="The finding you're looking for doesn't exist or has been deleted."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="space-y-4">
        <div className="flex items-start justify-between">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <SeverityBadge severity={finding.severity} />
              <h1 className="text-3xl font-bold text-surface-12">
                {finding.title}
              </h1>
            </div>
            <p className="text-surface-11">{finding.description}</p>
          </div>

          {/* Status Dropdown */}
          <div className="relative">
            <Button
              variant="outline"
              className="flex items-center gap-2"
              onClick={() => setShowStatusMenu(!showStatusMenu)}
            >
              <Badge className={cn('', STATUS_COLORS[finding.status as string])}>
                {STATUS_LABELS[finding.status as string]}
              </Badge>
              <ChevronDown className="h-4 w-4" />
            </Button>

            {showStatusMenu && (
              <div className="absolute right-0 top-12 z-50 w-48 rounded-lg border border-surface-6 bg-surface-1 shadow-lg">
                {Object.entries(STATUS_LABELS).map(([status, label]) => (
                  <button
                    key={status}
                    onClick={() => handleStatusChange(status)}
                    className={cn(
                      'w-full px-4 py-2 text-left text-sm transition-colors first:rounded-t-lg last:rounded-b-lg hover:bg-surface-3',
                      finding.status === status && 'bg-surface-2'
                    )}
                    disabled={updateMutation.isPending}
                  >
                    {label}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Metadata */}
        <div className="flex flex-wrap gap-6 text-sm text-surface-11">
          <div className="flex items-center gap-2">
            <Calendar className="h-4 w-4" />
            <span>
              Discovered:{' '}
              {new Date(finding.created_at).toLocaleDateString()}
            </span>
          </div>
          {finding.url && (
            <a
              href={finding.url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-blue-400 hover:text-blue-300"
            >
              <ArrowUpRight className="h-4 w-4" />
              {finding.url}
            </a>
          )}
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex flex-wrap gap-3">
        <Button
          variant="secondary"
          size="sm"
          onClick={handleMarkFalsePositive}
          disabled={
            falsPositiveMutation.isPending || finding.status === 'false_positive'
          }
          className="flex items-center gap-2"
        >
          <Flag className="h-4 w-4" />
          Mark False Positive
        </Button>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => setShowNoteInput(!showNoteInput)}
          className="flex items-center gap-2"
        >
          <MessageSquare className="h-4 w-4" />
          Add Note
        </Button>
        <CopyCurlButton findingId={finding.id} variant="outline" size="sm" />
        <Button
          variant="outline"
          size="sm"
          className="flex items-center gap-2"
        >
          <Download className="h-4 w-4" />
          Export
        </Button>
      </div>

      {/* Note Input */}
      {showNoteInput && (
        <Card className="border-surface-6 bg-surface-2">
          <CardContent className="space-y-3 pt-6">
            <textarea
              placeholder="Add a note about this finding..."
              className="h-24 w-full rounded-lg border border-surface-6 bg-surface-1 px-3 py-2 text-surface-12 placeholder-surface-9 focus:border-blue-500 focus:outline-none"
            />
            <div className="flex gap-2">
              <Button
                size="sm"
                onClick={() => setShowNoteInput(false)}
              >
                Save Note
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowNoteInput(false)}
              >
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <div className="space-y-4">
        <div className="flex border-b border-surface-6">
          {(
            ['evidence', 'ai_analysis', 'remediation', 'compliance', 'history'] as const
          ).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={cn(
                'px-4 py-2 text-sm font-medium transition-colors',
                activeTab === tab
                  ? 'border-b-2 border-blue-500 text-blue-400'
                  : 'text-surface-11 hover:text-surface-12'
              )}
            >
              {tab === 'ai_analysis'
                ? 'AI Analysis'
                : tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        {/* Evidence Tab */}
        {activeTab === 'evidence' && (
          <Card className="border-surface-6 bg-surface-1">
            <CardHeader>
              <CardTitle>Evidence</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              {finding.request ? (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-surface-12">
                      Request
                    </h3>
                    <button
                      onClick={() => copyToClipboard(JSON.stringify(finding.request, null, 2))}
                      className="text-surface-10 hover:text-surface-11"
                      title="Copy to clipboard"
                    >
                      <Copy className="h-4 w-4" />
                    </button>
                  </div>
                  <pre className="overflow-x-auto rounded-lg bg-surface-2 p-4 font-mono text-sm text-surface-11">
                    {JSON.stringify(finding.request, null, 2)}
                  </pre>
                </div>
              ) : null}

              {finding.response ? (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-surface-12">
                      Response
                    </h3>
                    <button
                      onClick={() => copyToClipboard(JSON.stringify(finding.response, null, 2))}
                      className="text-surface-10 hover:text-surface-11"
                      title="Copy to clipboard"
                    >
                      <Copy className="h-4 w-4" />
                    </button>
                  </div>
                  <pre className="overflow-x-auto rounded-lg bg-surface-2 p-4 font-mono text-sm text-surface-11">
                    {JSON.stringify(finding.response, null, 2)}
                  </pre>
                </div>
              ) : null}

              {!finding.request && !finding.response && (
                <p className="text-surface-10">No evidence available</p>
              )}
            </CardContent>
          </Card>
        )}

        {/* AI Analysis Tab */}
        {activeTab === 'ai_analysis' && finding.ai_analysis && (
          <AIAnalysisPanel analysis={finding.ai_analysis as any} />
        )}

        {/* Remediation Tab */}
        {activeTab === 'remediation' && (
          <Card className="border-surface-6 bg-surface-1">
            <CardHeader>
              <CardTitle>Remediation</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              {finding.ai_analysis?.defender ? (
                <div className="space-y-6">
                  <div>
                    <h3 className="mb-2 text-sm font-semibold text-surface-12">
                      Fix Summary
                    </h3>
                    <p className="text-sm text-surface-11">
                      {(finding.ai_analysis.defender as any).fix_summary}
                    </p>
                  </div>

                  {(finding.ai_analysis.defender as any).before_code && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <h4 className="text-sm font-semibold text-surface-12">
                          Before
                        </h4>
                        <button
                          onClick={() =>
                            copyToClipboard(
                              finding.ai_analysis?.defender?.before_code || ''
                            )
                          }
                          className="text-surface-10 hover:text-surface-11"
                        >
                          <Copy className="h-4 w-4" />
                        </button>
                      </div>
                      <pre className="overflow-x-auto rounded-lg bg-surface-2 p-4 font-mono text-sm text-surface-11">
                        {finding.ai_analysis.defender.before_code}
                      </pre>
                    </div>
                  )}

                  {(finding.ai_analysis.defender as any).after_code && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <h4 className="text-sm font-semibold text-surface-12">
                          After
                        </h4>
                        <button
                          onClick={() =>
                            copyToClipboard(
                              (finding.ai_analysis?.defender as any)?.after_code || ''
                            )
                          }
                          className="text-surface-10 hover:text-surface-11"
                        >
                          <Copy className="h-4 w-4" />
                        </button>
                      </div>
                      <pre className="overflow-x-auto rounded-lg bg-surface-2 p-4 font-mono text-sm text-surface-11">
                        {(finding.ai_analysis.defender as any).after_code}
                      </pre>
                    </div>
                  )}

                  {(finding.ai_analysis.defender as any).steps && (
                    <div>
                      <h4 className="mb-3 text-sm font-semibold text-surface-12">
                        Implementation Steps
                      </h4>
                      <ol className="space-y-2">
                        {(finding.ai_analysis.defender as any).steps.map(
                          (step: any, idx: number) => (
                            <li
                              key={idx}
                              className="flex gap-3 text-sm text-surface-11"
                            >
                              <span className="flex h-6 w-6 items-center justify-center rounded-full bg-surface-3 text-xs font-semibold">
                                {idx + 1}
                              </span>
                              <span>{step}</span>
                            </li>
                          )
                        )}
                      </ol>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-surface-10">
                  No remediation guidance available
                </p>
              )}
            </CardContent>
          </Card>
        )}

        {/* Compliance Tab */}
        {activeTab === 'compliance' && (
          <Card className="border-surface-6 bg-surface-1">
            <CardHeader>
              <CardTitle>Compliance Mappings</CardTitle>
            </CardHeader>
            <CardContent>
              {(finding.ai_analysis as any)?.analyst?.framework_mappings &&
              Object.keys((finding.ai_analysis as any).analyst.framework_mappings)
                .length > 0 ? (
                <div className="space-y-4">
                  {Object.entries(
                    (finding.ai_analysis as any).analyst.framework_mappings
                  ).map(([framework, controls]: [string, any]) => (
                    <div key={framework} className="space-y-2">
                      <h4 className="text-sm font-semibold text-surface-12">
                        {framework}
                      </h4>
                      <div className="flex flex-wrap gap-2">
                        {Array.isArray(controls)
                          ? controls.map((control, idx) => (
                              <Badge
                                key={idx}
                                variant="secondary"
                                className="bg-blue-500/20 text-blue-300"
                              >
                                {control}
                              </Badge>
                            ))
                          : typeof controls === 'object'
                            ? Object.entries(controls).map(([key, val]) => (
                                <Badge
                                  key={key}
                                  variant="secondary"
                                  className="bg-blue-500/20 text-blue-300"
                                >
                                  {key}: {String(val)}
                                </Badge>
                              ))
                            : (
                                <Badge
                                  variant="secondary"
                                  className="bg-blue-500/20 text-blue-300"
                                >
                                  {String(controls)}
                                </Badge>
                              )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-surface-10">No compliance mappings found</p>
              )}
            </CardContent>
          </Card>
        )}

        {/* History Tab */}
        {activeTab === 'history' && (
          <Card className="border-surface-6 bg-surface-1">
            <CardHeader>
              <CardTitle>Status History</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex gap-4">
                  <div className="flex flex-col items-center">
                    <div className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-500/20">
                      <AlertCircle className="h-4 w-4 text-blue-400" />
                    </div>
                    <div className="h-12 w-0.5 bg-surface-6" />
                  </div>
                  <div className="pb-4">
                    <p className="font-semibold text-surface-12">Finding Created</p>
                    <p className="text-sm text-surface-10">
                      {new Date(finding.created_at).toLocaleString()}
                    </p>
                  </div>
                </div>

                {finding.updated_at &&
                  new Date(finding.updated_at).getTime() !==
                    new Date(finding.created_at).getTime() && (
                    <div className="flex gap-4">
                      <div className="flex flex-col items-center">
                        <div className="flex h-8 w-8 items-center justify-center rounded-full bg-green-500/20">
                          <CheckCircle className="h-4 w-4 text-green-400" />
                        </div>
                      </div>
                      <div>
                        <p className="font-semibold text-surface-12">
                          Last Updated
                        </p>
                        <p className="text-sm text-surface-10">
                          {new Date(finding.updated_at).toLocaleString()}
                        </p>
                        <p className="text-xs text-surface-9">
                          Status: {STATUS_LABELS[finding.status as string]}
                        </p>
                      </div>
                    </div>
                  )}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
