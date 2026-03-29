import { cn } from '@/utils/formatters'

interface FindingStatusBadgeProps {
  status: string
  className?: string
}

const STATUS_CONFIG: Record<string, { label: string; color: string }> = {
  new: { label: 'NEW', color: 'bg-blue-500/10 text-blue-500' },
  confirmed: { label: 'CONFIRMED', color: 'bg-orange-500/10 text-orange-500' },
  in_progress: { label: 'IN PROGRESS', color: 'bg-yellow-500/10 text-yellow-500' },
  resolved: { label: 'RESOLVED', color: 'bg-green-500/10 text-green-500' },
  verified: { label: 'VERIFIED', color: 'bg-emerald-500/10 text-emerald-500' },
  false_positive: { label: 'FALSE POSITIVE', color: 'bg-gray-500/10 text-gray-500' },
  accepted_risk: { label: 'ACCEPTED RISK', color: 'bg-purple-500/10 text-purple-500' },
}

export function FindingStatusBadge({ status, className }: FindingStatusBadgeProps) {
  const config = STATUS_CONFIG[status.toLowerCase()] || STATUS_CONFIG.new

  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-1 rounded-md text-xs font-medium',
        config.color,
        className
      )}
    >
      {config.label}
    </span>
  )
}
