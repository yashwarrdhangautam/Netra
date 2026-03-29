import { Shield, AlertTriangle, AlertCircle, Info } from 'lucide-react'
import { cn } from '@/utils/formatters'

interface SeverityBadgeProps {
  severity: string
  className?: string
}

const SEVERITY_CONFIG: Record<string, { icon: React.ElementType; color: string }> = {
  critical: { icon: Shield, color: 'bg-severity-critical text-white' },
  high: { icon: AlertTriangle, color: 'bg-severity-high text-black' },
  medium: { icon: AlertCircle, color: 'bg-severity-medium text-black' },
  low: { icon: Info, color: 'bg-severity-low text-white' },
  info: { icon: Info, color: 'bg-severity-info text-white' },
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const config = SEVERITY_CONFIG[severity.toLowerCase()] || SEVERITY_CONFIG.info
  const Icon = config.icon

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium uppercase',
        config.color,
        className
      )}
    >
      <Icon className="w-3 h-3" />
      {severity}
    </span>
  )
}
