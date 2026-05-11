import { AlertTriangle, Check, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { cn } from '@/utils/formatters'

interface AtomProps {
  children: React.ReactNode
  className?: string
}

export function SeverityBadge({ severity, cvss }: { severity: string; cvss?: number | null }) {
  const colors: Record<string, string> = {
    critical: 'bg-severity-critical text-white',
    high: 'bg-severity-high text-white',
    medium: 'bg-severity-medium text-black',
    low: 'bg-severity-low text-white',
    info: 'bg-severity-info text-white',
  }
  return (
    <span className={cn('inline-flex h-[18px] items-center gap-1 rounded px-2 text-xs font-semibold leading-none', colors[severity] || colors.info)}>
      <AlertTriangle className="h-3 w-3" />
      {severity}
      {typeof cvss === 'number' ? <span className="font-mono tabular-nums">{cvss.toFixed(1)}</span> : null}
    </span>
  )
}

export function ScopeVerdictChip({ allowed }: { allowed: boolean | null }) {
  if (allowed === null) {
    return (
      <span className="inline-flex h-5 items-center gap-1 rounded bg-amber-600 px-2 font-mono text-xs text-white">
        <ShieldQuestion className="h-3 w-3" /> ?
      </span>
    )
  }
  return allowed ? (
    <span className="inline-flex h-5 items-center gap-1 rounded bg-green-600 px-2 font-mono text-xs text-white">
      <ShieldCheck className="h-3 w-3" /> IN
    </span>
  ) : (
    <span className="inline-flex h-5 items-center gap-1 rounded bg-red-600 px-2 font-mono text-xs text-white">
      <ShieldAlert className="h-3 w-3" /> OUT
    </span>
  )
}

export function StatusPill({ children, className }: AtomProps) {
  return (
    <span className={cn('inline-flex h-5 items-center gap-1 rounded bg-surface-3 px-2 text-xs font-medium text-muted-foreground', className)}>
      <Check className="h-3 w-3" />
      {children}
    </span>
  )
}

export function CommandBlock({ command }: { command: string }) {
  return (
    <code className="block overflow-x-auto rounded border border-border bg-surface-2 px-3 py-2 font-mono text-xs text-muted-foreground">
      {command}
    </code>
  )
}
