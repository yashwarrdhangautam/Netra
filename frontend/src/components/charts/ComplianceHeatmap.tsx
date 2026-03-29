import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'

interface Control {
  id: string
  name: string
  status: 'pass' | 'fail' | 'partial' | 'not_assessed'
}

interface ComplianceHeatmapProps {
  controls: Control[]
  className?: string
}

const STATUS_COLORS = {
  pass: '#10b981',
  fail: '#ef4444',
  partial: '#f59e0b',
  not_assessed: '#374151',
}

export function ComplianceHeatmap({ controls, className }: ComplianceHeatmapProps) {
  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>Compliance Heatmap</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-4 gap-2">
          {controls.map((control) => (
            <div
              key={control.id}
              className="flex flex-col items-center justify-center p-3 rounded-lg border border-border bg-surface-2"
              title={control.name}
            >
              <div
                className="w-8 h-8 rounded-full mb-2"
                style={{ backgroundColor: STATUS_COLORS[control.status] }}
              />
              <div className="text-xs font-medium">{control.id}</div>
              <div className="text-xs text-muted-foreground capitalize">{control.status.replace('_', ' ')}</div>
            </div>
          ))}
        </div>
        <div className="flex gap-4 mt-4 justify-center">
          {Object.entries(STATUS_COLORS).map(([status, color]) => (
            <div key={status} className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
              <span className="text-xs text-muted-foreground capitalize">{status.replace('_', ' ')}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
