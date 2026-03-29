import { cn } from '@/utils/formatters'

interface ScanProgressBarProps {
  progress: number
  status: string
  className?: string
}

const STATUS_COLORS: Record<string, string> = {
  running: 'bg-accent',
  completed: 'bg-status-pass',
  failed: 'bg-status-fail',
  paused: 'bg-severity-medium',
  pending: 'bg-muted-foreground',
}

export function ScanProgressBar({ progress, status, className }: ScanProgressBarProps) {
  const color = STATUS_COLORS[status.toLowerCase()] || STATUS_COLORS.pending

  return (
    <div className={cn('w-full', className)}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium capitalize">{status}</span>
        <span className="text-sm text-muted-foreground">{Math.round(progress)}%</span>
      </div>
      <div className="h-2 bg-surface-2 rounded-full overflow-hidden">
        <div
          className={cn('h-full transition-all duration-300', color)}
          style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
        />
      </div>
    </div>
  )
}
