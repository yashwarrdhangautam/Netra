/**
 * Finding types for NETRA security findings
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type FindingStatus = 
  | 'new' 
  | 'confirmed' 
  | 'in_progress' 
  | 'resolved' 
  | 'verified' 
  | 'false_positive' 
  | 'accepted_risk'

export interface Finding {
  id: string
  scan_id: string
  title: string
  description: string
  severity: Severity
  status: FindingStatus
  cvss_score?: number
  cvss_vector?: string
  cwe_id?: string
  cve_ids?: string[]
  url?: string
  parameter?: string
  evidence?: FindingEvidence
  tool_source: string
  confidence: number
  remediation?: string
  ai_analysis?: AIAnalysis
  tags?: string[]
  assignee?: string
  notes?: string
  dedup_hash?: string
  created_at: string
  updated_at: string
  
  // Request/Response data for web findings
  request?: HTTPRequest
  response?: HTTPResponse
  
  // Code analysis data
  fix_summary?: string
  before_code?: CodeDiff
  after_code?: CodeDiff
  steps?: RemediationStep[]
  
  // Compliance mappings
  framework_mappings?: FrameworkMapping[]
}

export interface FindingEvidence {
  method?: string
  url?: string
  headers?: Record<string, string>
  body?: unknown
  cookies?: Record<string, string>
  user_agent?: string
  [key: string]: unknown
}

export interface HTTPRequest {
  method: string
  url: string
  headers: Record<string, string>
  body?: string
}

export interface HTTPResponse {
  status_code: number
  headers: Record<string, string>
  body?: string
}

export interface AttackerAnalysis {
  exploitability?: string
  business_impact?: string
  mitre_techniques?: string[]
  confidence?: number
  attack_chains?: { steps?: string[] }[]
}

export interface DefenderAnalysis {
  root_cause?: string
  immediate_fix?: string
  long_term_fix?: string
  priority?: string
  confidence?: number
  fix_summary?: string
  before_code?: string
  after_code?: string
  steps?: string[]
}

export interface AnalystAnalysis {
  framework_mappings?: Record<string, unknown[]>
  regulatory_risk?: string
  compliance_priority?: string
  confidence?: number
}

export interface SkepticAnalysis {
  verdict?: string
  reasoning?: string
  confidence?: number
}

export interface AIAnalysis {
  summary?: string
  impact?: string
  remediation?: string
  confidence?: number
  personas?: PersonaResponse[]
  attacker?: AttackerAnalysis
  defender?: DefenderAnalysis
  analyst?: AnalystAnalysis
  skeptic?: SkepticAnalysis
  consensus?: { status?: string; final_confidence?: number }
}

export interface PersonaResponse {
  persona: string
  response: string
  confirmed: boolean
}

export interface CodeDiff {
  language: string
  code: string
  file_path?: string
}

export interface RemediationStep {
  step: number
  description: string
  code?: string
}

export interface FrameworkMapping {
  framework: string
  control_id: string
  control_name: string
  status: 'compliant' | 'non_compliant' | 'partial'
}

export interface FindingList {
  findings: Finding[]
  total: number
  page: number
  page_size: number
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  per_page: number
  pages: number
}
