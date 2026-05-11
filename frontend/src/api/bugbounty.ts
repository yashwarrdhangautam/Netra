import apiClient from './client'

export type DoctorStatus = 'ok' | 'warn' | 'error'
export type BBPlatform = 'hackerone' | 'bugcrowd' | 'intigriti' | 'yeswehack' | 'private'
export type HuntProfile = 'passive' | 'active'

export interface DoctorCheck {
  name: string
  status: DoctorStatus
  detail: string
}

export interface BBCounters {
  scope_rules: number
  assets: number
  findings_open: number
  submissions_draft: number
}

export interface BBProgram {
  id: string
  platform: BBPlatform
  handle: string
  name: string
  policy_url: string | null
  payout_min: number | null
  payout_max: number | null
  currency: string
  scope_synced_at: string | null
  active: boolean
  created_at: string
  updated_at: string
  counts: BBCounters
}

export interface CreateProgramPayload {
  platform: BBPlatform
  handle: string
  name?: string
  policy_url?: string
  payout_min?: number
  payout_max?: number
  currency?: string
  auto_sync_scope?: boolean
}

export interface ScopeDiff {
  added: Array<Record<string, unknown>>
  removed: Array<Record<string, unknown>>
  unchanged_count: number
  has_changes: boolean
  warning: string | null
}

export interface BBScopeRule {
  id: string
  program_id: string
  rule_type: 'in' | 'out'
  asset_type: string
  pattern: string
  severity_cap: string | null
  notes: string | null
  active: boolean
  synced_from_platform: boolean
  created_at: string
  updated_at: string
}

export interface ScopeDecision {
  allowed: boolean
  reason: string
  matched_rule: Record<string, unknown> | null
  severity_cap: string | null
  parsed: Record<string, unknown> | null
  notes: string[]
}

export interface Hunt {
  id: string
  name: string
  status: string
  profile: string
  mode: 'fixed' | 'agentic'
  dry_run: boolean
  program_id: string | null
  target_id: string
  started_at: string | null
  completed_at: string | null
  created_at: string
  phases: Array<Record<string, unknown>>
  assets_discovered: number
  blocked_count: number
  findings_count: number
}

export interface Dashboard {
  active_programs: number
  scope_rules: number
  assets: number
  open_findings: number
  submissions_draft: number
  out_of_scope_blocks_24h: number
  recent_hunts: Hunt[]
  doctor: DoctorCheck[]
}

export interface TrendBucket {
  name: string
  count: number
}

export interface TrendSummary {
  window_days: number
  total_reports: number
  total_writeups: number
  total_advisories: number
  top_vuln_classes: TrendBucket[]
  top_tech: TrendBucket[]
  top_programs: TrendBucket[]
}

export interface TriageRow {
  id: string
  title: string
  asset: string | null
  vuln_class: string
  severity: string
  status: string
  cvss: number | null
  bounty_hunter: Record<string, unknown>
  skeptic_vetoed: boolean
  dedup: {
    exact: Record<string, unknown> | null
    similar: Array<Record<string, unknown>>
  }
  created_at: string
}

export interface FindingCorpusContext {
  finding_id: string
  similar_reports: string[]
}

export interface Submission {
  id: string
  finding_id: string
  program_id: string
  title: string
  status: string
  severity: string
  payout_expected: number | null
  payout_actual: number | null
  currency: string
  created_at: string
  updated_at: string
}

export interface SubmissionDetail extends Submission {
  draft_md: string | null
  cvss_vector: string | null
  platform_report_id: string | null
  submitted_at: string | null
  verdict_at: string | null
  verdict_notes: string | null
  metadata_: Record<string, unknown> | null
}

export interface ScopeBlock {
  id: string
  scan_id: string
  program_id: string | null
  timestamp: string
  tool: string
  target: string | null
  decision: string
  reason: string | null
}

export interface EvidenceItem {
  id: string
  finding_id: string
  program_id: string
  filename: string
  mime_type: string
  sha256: string
  size_bytes: number
  redaction_count: number
  encrypted: boolean
  metadata_: Record<string, unknown> | null
  created_at: string
  updated_at: string
}

export interface ReplayResult {
  id: string
  evidence_id: string
  verifier_id: string
  status: string
  status_code: number | null
  latency_ms: number | null
  diff: Record<string, unknown> | null
  error_message: string | null
  created_at: string
}

export interface VerifierSpec {
  id: string
  vuln_class: string
  description: string
  methods: string[]
  will_do: string[]
  will_not_do: string[]
  requires: string[]
}

export interface GraphPayload {
  nodes: Array<Record<string, unknown>>
  edges: Array<Record<string, unknown>>
  warning?: string
}

export interface HuntExplainStep {
  step_n: number
  status: string
  tool_chosen: string | null
  decision_rationale: string | null
  observations_in: Record<string, unknown>
  observations_out: Record<string, unknown>
  metadata: Record<string, unknown>
}

export interface HuntExplainPayload {
  scan_id: string
  summary: string | null
  focus_areas: string[]
  recommended_tools: string[]
  retrieval_hits: Array<Record<string, unknown>>
  attack_paths: Array<Record<string, unknown>>
  report_focus: string[]
  steps: HuntExplainStep[]
}

export interface PlanPreviewPayload {
  rationale: string
  coordination: Record<string, unknown>
  steps: Array<Record<string, unknown>>
}

export const bugBountyApi = {
  dashboard: async (): Promise<Dashboard> => {
    const { data } = await apiClient.get<Dashboard>('/api/v1/bb/dashboard')
    return data
  },
  doctor: async (): Promise<DoctorCheck[]> => {
    const { data } = await apiClient.get<DoctorCheck[]>('/api/v1/bb/doctor')
    return data
  },
  trends: async (days = 7): Promise<TrendSummary> => {
    const { data } = await apiClient.get<TrendSummary>('/api/v1/bb/trends', {
      params: { days },
    })
    return data
  },
  programs: async (): Promise<BBProgram[]> => {
    const { data } = await apiClient.get<BBProgram[]>('/api/v1/bb/programs')
    return data
  },
  createProgram: async (payload: CreateProgramPayload): Promise<BBProgram> => {
    const { data } = await apiClient.post<BBProgram>('/api/v1/bb/programs', payload)
    return data
  },
  syncScope: async (programId: string): Promise<ScopeDiff> => {
    const { data } = await apiClient.post<ScopeDiff>(`/api/v1/bb/programs/${programId}/sync-scope`)
    return data
  },
  scopeRules: async (programId?: string): Promise<BBScopeRule[]> => {
    const { data } = await apiClient.get<BBScopeRule[]>('/api/v1/bb/scope/rules', {
      params: { program_id: programId || undefined, active: true },
    })
    return data
  },
  checkScope: async (programId: string, target: string): Promise<ScopeDecision> => {
    const { data } = await apiClient.post<ScopeDecision>('/api/v1/bb/scope/check', {
      program_id: programId,
      target,
    })
    return data
  },
  hunts: async (programId?: string): Promise<Hunt[]> => {
    const { data } = await apiClient.get<Hunt[]>('/api/v1/bb/hunts', {
      params: { program_id: programId || undefined },
    })
    return data
  },
  createHunt: async (programId: string, profile: HuntProfile, options: Record<string, unknown>): Promise<Hunt> => {
    const { data } = await apiClient.post<Hunt>('/api/v1/bb/hunts', {
      program_id: programId,
      profile,
      options,
    })
    return data
  },
  previewPlan: async (programId: string, asset?: string): Promise<PlanPreviewPayload> => {
    const { data } = await apiClient.post<PlanPreviewPayload>('/api/v1/bb/hunts/plan-preview', {
      program_id: programId,
      asset,
    })
    return data
  },
  cancelHunt: async (huntId: string): Promise<Hunt> => {
    const { data } = await apiClient.post<Hunt>(`/api/v1/bb/hunts/${huntId}/cancel`)
    return data
  },
  explainHunt: async (huntId: string): Promise<HuntExplainPayload> => {
    const { data } = await apiClient.get<HuntExplainPayload>(`/api/v1/bb/hunts/${huntId}/explain`)
    return data
  },
  triage: async (params?: { programId?: string; includeVetoed?: boolean; graphAware?: boolean }): Promise<TriageRow[]> => {
    const { data } = await apiClient.get<TriageRow[]>('/api/v1/bb/triage', {
      params: {
        program_id: params?.programId,
        include_vetoed: params?.includeVetoed,
        graph_aware: params?.graphAware,
      },
    })
    return data
  },
  findingCorpusContext: async (findingId: string): Promise<FindingCorpusContext> => {
    const { data } = await apiClient.get<FindingCorpusContext>(`/api/v1/bb/findings/${findingId}/similar-reports`)
    return data
  },
  submissions: async (programId?: string): Promise<Submission[]> => {
    const { data } = await apiClient.get<Submission[]>('/api/v1/bb/submissions', {
      params: { program_id: programId || undefined },
    })
    return data
  },
  createSubmission: async (findingId: string, force = false, includePoc = false): Promise<SubmissionDetail> => {
    const { data } = await apiClient.post<SubmissionDetail>('/api/v1/bb/submissions', {
      finding_id: findingId,
      force,
      include_poc: includePoc,
      formats: ['md', 'docx'],
    })
    return data
  },
  submission: async (submissionId: string): Promise<SubmissionDetail> => {
    const { data } = await apiClient.get<SubmissionDetail>(`/api/v1/bb/submissions/${submissionId}`)
    return data
  },
  updateSubmission: async (submissionId: string, payload: Partial<Pick<SubmissionDetail, 'title' | 'draft_md' | 'platform_report_id' | 'verdict_notes'>>): Promise<SubmissionDetail> => {
    const { data } = await apiClient.patch<SubmissionDetail>(`/api/v1/bb/submissions/${submissionId}`, payload)
    return data
  },
  transitionSubmission: async (submissionId: string, toStatus: string, notes?: string): Promise<SubmissionDetail> => {
    const { data } = await apiClient.post<SubmissionDetail>(`/api/v1/bb/submissions/${submissionId}/transition`, {
      to_status: toStatus,
      notes,
    })
    return data
  },
  renderSubmission: async (submissionId: string, format: 'md' | 'docx' | 'pdf'): Promise<{ format: string; path: string; download_url: string | null }> => {
    const { data } = await apiClient.post<{ format: string; path: string; download_url: string | null }>(`/api/v1/bb/submissions/${submissionId}/render`, { format })
    return data
  },
  verdictSubmission: async (submissionId: string, verdict: 'paid' | 'dup' | 'na' | 'info', payoutActual?: number, notes?: string): Promise<SubmissionDetail> => {
    const { data } = await apiClient.post<SubmissionDetail>(`/api/v1/bb/submissions/${submissionId}/verdict`, {
      verdict,
      payout_actual: payoutActual,
      notes,
    })
    return data
  },
  scopeBlocks: async (): Promise<ScopeBlock[]> => {
    const { data } = await apiClient.get<ScopeBlock[]>('/api/v1/bb/audit/scope-blocks')
    return data
  },
  uiActions: async (): Promise<Array<Record<string, unknown>>> => {
    const { data } = await apiClient.get<Array<Record<string, unknown>>>('/api/v1/bb/audit/ui-actions')
    return data
  },
  evidence: async (findingId: string): Promise<EvidenceItem[]> => {
    const { data } = await apiClient.get<EvidenceItem[]>(`/api/v1/bb/findings/${findingId}/evidence`)
    return data
  },
  uploadEvidence: async (findingId: string, file: File): Promise<EvidenceItem> => {
    const form = new FormData()
    form.append('file', file)
    const { data } = await apiClient.post<EvidenceItem>(`/api/v1/bb/findings/${findingId}/evidence`, form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data
  },
  replayEvidence: async (evidenceId: string, verifierId: string, typedConfirm: string): Promise<ReplayResult> => {
    const { data } = await apiClient.post<ReplayResult>(`/api/v1/bb/evidence/${evidenceId}/replay`, {
      verifier_id: verifierId,
      typed_confirm: typedConfirm,
    })
    return data
  },
  verifiers: async (): Promise<VerifierSpec[]> => {
    const { data } = await apiClient.get<VerifierSpec[]>('/api/v1/bb/settings/verifiers')
    return data
  },
  programGraph: async (programId: string): Promise<GraphPayload> => {
    const { data } = await apiClient.get<GraphPayload>(`/api/v1/bb/graph/program/${programId}`)
    return data
  },
  codebaseGraph: async (): Promise<GraphPayload> => {
    const { data } = await apiClient.get<GraphPayload>('/api/v1/bb/graph/codebase')
    return data
  },
  reindexGraph: async (kind: 'codebase' | 'program', id?: string): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.post<Record<string, unknown>>('/api/v1/bb/graph/reindex', { kind, id })
    return data
  },
  killSwitch: async (confirm: string): Promise<{ status: string; count: number }> => {
    const { data } = await apiClient.post<{ status: string; count: number }>('/api/v1/bb/kill-switch', { confirm })
    return data
  },
}
