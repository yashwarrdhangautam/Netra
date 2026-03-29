// TypeScript types matching Pydantic schemas from backend

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type FindingStatus = 'new' | 'confirmed' | 'in_progress' | 'resolved' | 'verified' | 'false_positive' | 'accepted_risk'
export type ScanStatus = 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled'
export type ScanProfile = 'quick' | 'standard' | 'deep' | 'api_only' | 'cloud' | 'mobile' | 'container' | 'ai_llm' | 'custom'

export interface Scan {
  id: string
  name: string
  status: ScanStatus
  profile: ScanProfile
  target_id: string
  started_at: string | null
  completed_at: string | null
  created_at: string
  updated_at: string
}

export interface ScanList {
  id: string
  name: string
  status: ScanStatus
  profile: ScanProfile
  created_at: string
}

export interface Finding {
  id: string
  scan_id: string
  title: string
  description: string
  severity: Severity
  status: FindingStatus
  cvss_score: number | null
  cvss_vector: string | null
  cwe_id: string | null
  cve_ids: string[] | null
  url: string | null
  parameter: string | null
  evidence: Record<string, unknown> | null
  tool_source: string
  confidence: number
  remediation: string | null
  ai_analysis: Record<string, unknown> | null
  tags: string[] | null
  assignee: string | null
  notes: string | null
  created_at: string
  updated_at: string
}

export interface FindingList {
  id: string
  scan_id: string
  title: string
  severity: Severity
  status: FindingStatus
  tool_source: string
  created_at: string
}

export interface Target {
  id: string
  name: string
  target_type: 'domain' | 'ip' | 'url' | 'ip_range' | 'domain_list'
  value: string
  created_at: string
}

export interface Report {
  id: string
  scan_id: string
  report_type: string
  status: 'pending' | 'generating' | 'completed' | 'failed'
  file_path: string | null
  file_size: number | null
  created_at: string
}

export interface ComplianceScore {
  scan_id: string
  framework: string
  score: number
  total_controls: number
  passed: number
  failed: number
  failed_controls: Array<{ control_id: string; control_name: string }>
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  per_page: number
  pages: number
}

export interface DashboardStats {
  total_scans: number
  total_findings: number
  findings_by_severity: Record<Severity, number>
  risk_score: number
  risk_grade: string
  sla_breaches: number
  recent_scans: ScanList[]
}

export interface AttackChain {
  chain_id: string
  name: string
  description: string
  steps: Array<{
    finding_id: string
    finding_title: string
    order: number
  }>
  combined_impact: string
}
