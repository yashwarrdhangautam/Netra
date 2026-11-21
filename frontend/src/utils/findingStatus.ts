/** Finding triage states and their labels (backend FindingStatus). */
export const STATUS_LABELS: Record<string, string> = {
  new: 'New',
  needs_review: 'Needs review',
  confirmed: 'Open (confirmed)',
  in_progress: 'In progress',
  resolved: 'Resolved',
  verified: 'Verified fixed',
  false_positive: 'False positive',
  accepted_risk: 'Accepted risk',
}
