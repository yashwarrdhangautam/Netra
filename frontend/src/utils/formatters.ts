import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(dateString: string): string {
  const date = new Date(dateString)
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

export function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMins / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 7) return `${diffDays}d ago`
  return formatDate(dateString)
}

export function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: 'text-severity-critical bg-severity-critical/10',
    high: 'text-severity-high bg-severity-high/10',
    medium: 'text-severity-medium bg-severity-medium/10',
    low: 'text-severity-low bg-severity-low/10',
    info: 'text-severity-info bg-severity-info/10',
  }
  return colors[severity] || colors.info
}

export function getStatusColor(status: string): string {
  const colors: Record<string, string> = {
    completed: 'text-status-pass',
    pass: 'text-status-pass',
    verified: 'text-status-pass',
    resolved: 'text-status-pass',
    failed: 'text-status-fail',
    fail: 'text-status-fail',
    false_positive: 'text-status-fail',
    running: 'text-accent',
    pending: 'text-muted-foreground',
    new: 'text-accent',
    confirmed: 'text-accent',
    in_progress: 'text-accent',
  }
  return colors[status] || 'text-muted-foreground'
}

export function truncate(str: string, length: number): string {
  if (str.length <= length) return str
  return str.slice(0, length) + '...'
}
