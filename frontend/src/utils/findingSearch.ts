/** URL filters for the findings list. Every value is optional; unknown keys are dropped. */
export interface FindingSearch {
  scan_id?: string
  target_id?: string
  severity?: string
  status?: string
  tool_source?: string
  cwe_id?: string
  cve?: string
  q?: string
  page?: number
}

const TEXT_KEYS = ['scan_id', 'target_id', 'severity', 'status', 'tool_source', 'cwe_id', 'cve', 'q'] as const

export function parseFindingSearch(search: Record<string, unknown>): FindingSearch {
  const out: FindingSearch = {}
  for (const key of TEXT_KEYS) {
    const value = search[key]
    if (typeof value === 'string' && value.trim()) out[key] = value.trim().slice(0, 200)
  }
  const page = Number(search.page)
  if (Number.isInteger(page) && page > 1) out.page = page
  return out
}

/** The same filters as API query params (drops empty values). */
export function toFindingFilters(search: FindingSearch): Record<string, string | number> {
  const params: Record<string, string | number> = {}
  for (const [key, value] of Object.entries(search)) {
    if (value !== undefined && value !== '') params[key] = value
  }
  return params
}
