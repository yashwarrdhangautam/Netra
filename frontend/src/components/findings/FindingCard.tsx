import { useNavigate } from '@tanstack/react-router'
import { Card, CardContent } from '@/components/ui/Card'
import { SeverityBadge } from './SeverityBadge'
import { cn } from '@/utils/formatters'

interface Finding {
  id: string
  title: string
  severity: string
  url?: string | null
  tool_source: string
  confidence: number
}

interface FindingCardProps {
  finding: Finding
  className?: string
}

export function FindingCard({ finding, className }: FindingCardProps) {
  const navigate = useNavigate()

  return (
    <Card
      className={cn('cursor-pointer transition-colors hover:bg-surface-2', className)}
      onClick={() => navigate({ to: `/findings/${finding.id}` })}
    >
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <SeverityBadge severity={finding.severity} />
              <span className="text-xs text-muted-foreground">{finding.tool_source}</span>
            </div>
            <h3 className="font-medium truncate">{finding.title}</h3>
            {finding.url && (
              <p className="text-sm text-muted-foreground truncate mt-1">{finding.url}</p>
            )}
          </div>
          <div className="text-right">
            <div className="text-sm text-muted-foreground">Confidence</div>
            <div className="text-lg font-medium">{finding.confidence}%</div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
