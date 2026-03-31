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
  body?: any
  cookies?: Record<string, string>
  user_agent?: string
  [key: string]: any
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

export interface AIAnalysis {
  summary?: string
  impact?: string
  remediation?: string
  confidence?: number
  personas?: PersonaResponse[]

  // Attacker persona analysis
  attacker?: {
    vote?: string
    rationale?: string
    attack_vector?: string
    exploit_availability?: string
    impact?: string
    exploitability?: string
    business_impact?: string
    mitre_techniques?: string[]
    confidence?: number
    attack_chains?: AttackChain[]
  }

  // Defender persona analysis
  defender?: {
    vote?: string
    rationale?: string
    detection_method?: string
    remediation_cost?: string
    fix_summary?: string
    before_code?: string
    after_code?: string
    steps?: string[]
    root_cause?: string
    immediate_fix?: string
    long_term_fix?: string
    priority?: string
    confidence?: number
  }

  // Analyst persona analysis
  analyst?: {
    vote?: string
    rationale?: string
    business_impact?: string
    cvss_justification?: string
    framework_mappings?: Record<string, string[] | Record<string, string> | string>
    regulatory_risk?: string
    compliance_priority?: string
    confidence?: number
  }

  // Skeptic persona analysis
  skeptic?: {
    vote?: string
    rationale?: string
    detection_confidence?: string
    false_positive_likelihood?: string
    verdict?: string
    reasoning?: string
    confidence?: number
  }

  // Consensus result
  consensus?: {
    status?: string
    final_confidence?: number
  }
}

export interface AttackChain {
  name: string
  description: string
  steps: string[]
  combined_cvss?: number
  narrative?: string
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
  data: T[]
  total: number
  page: number
  page_size: number
  has_more: boolean
}
