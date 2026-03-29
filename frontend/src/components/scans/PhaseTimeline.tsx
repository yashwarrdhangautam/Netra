import { CheckCircle, Circle, Loader2, XCircle, PauseCircle } from 'lucide-react'
import { cn } from '@/utils/formatters'

interface Phase {
  phase_type: string
  status: string
  progress: number
  findings_count: number
  started_at?: string | null
  completed_at?: string | null
}

interface PhaseTimelineProps {
  phases: Phase[]
  className?: string
}

const PHASE_ICONS: Record<string, React.ElementType> = {
  recon_subdomains: Circle,
  recon_discovery: Circle,
  recon_ports: Circle,
  vuln_scan: Circle,
  pentest: Circle,
  ai_analysis: Circle,
  sast: Circle,
  secrets: Circle,
  dependencies: Circle,
  cspm: Circle,
  container: Circle,
  iac: Circle,
  ai_llm: Circle,
}

const STATUS_ICONS: Record<string, React.ElementType> = {
  completed: CheckCircle,
  running: Loader2,
  failed: XCircle,
  paused: PauseCircle,
  pending: Circle,
}

export function PhaseTimeline({ phases, className }: PhaseTimelineProps) {
  return (
    <div className={cn('space-y-4', className)}>
      {phases.map((phase, index) => {
        const Icon = STATUS_ICONS[phase.status.toLowerCase()] || Circle
        const isRunning = phase.status.toLowerCase() === 'running'
        const isCompleted = phase.status.toLowerCase() === 'completed'

        return (
          <div key={phase.phase_type} className="flex gap-4">
            <div className="flex flex-col items-center">
              <Icon
                className={cn(
                  'w-6 h-6',
                  isCompleted ? 'text-status-pass' : isRunning ? 'text-accent animate-spin' : 'text-muted-foreground'
                )}
              />
              {index < phases.length - 1 && (
                <div className={cn('w-0.5 h-8 mt-2', isCompleted ? 'bg-status-pass' : 'bg-border')} />
              )}
            </div>
            <div className="flex-1 pb-4">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium capitalize">{phase.phase_type.replace(/_/g, ' ')}</span>
                <span className="text-xs text-muted-foreground">{phase.findings_count} findings</span>
              </div>
              <div className="mt-1 h-1.5 bg-surface-2 rounded-full overflow-hidden">
                <div
                  className={cn('h-full transition-all', isCompleted ? 'bg-status-pass' : 'bg-accent')}
                  style={{ width: `${phase.progress}%` }}
                />
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}
