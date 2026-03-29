import { cn } from '@/utils/formatters'

interface ScanStatusBadgeProps {
  status: string
  className?: string
}

const STATUS_CONFIG: Record<string, { label: string; color: string; pulse?: boolean }> = {
  pending: { label: 'PENDING', color: 'bg-gray-500/10 text-gray-500' },
  running: { label: 'RUNNING', color: 'bg-accent/10 text-accent', pulse: true },
  paused: { label: 'PAUSED', color: 'bg-yellow-500/10 text-yellow-500' },
  completed: { label: 'COMPLETED', color: 'bg-status-pass/10 text-status-pass' },
  failed: { label: 'FAILED', color: 'bg-status-fail/10 text-status-fail' },
  cancelled: { label: 'CANCELLED', color: 'bg-gray-500/10 text-gray-500 line-through' },
}

export function ScanStatusBadge({ status, className }: ScanStatusBadgeProps) {
  const config = STATUS_CONFIG[status.toLowerCase()] || STATUS_CONFIG.pending

  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-1 rounded-md text-xs font-medium',
        config.color,
        config.pulse && 'animate-pulse',
        className
      )}
    >
      {config.label}
    </span>
  )
}
