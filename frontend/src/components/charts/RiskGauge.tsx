import { Card, CardContent } from '@/components/ui/Card'

interface RiskGaugeProps {
  score: number
  className?: string
}

function getGrade(score: number): string {
  if (score >= 80) return 'F'
  if (score >= 60) return 'D'
  if (score >= 40) return 'C'
  if (score >= 20) return 'B'
  return 'A'
}

function getColor(score: number): string {
  if (score >= 80) return '#ef4444'
  if (score >= 60) return '#f97316'
  if (score >= 40) return '#f59e0b'
  if (score >= 20) return '#3b82f6'
  return '#10b981'
}

export function RiskGauge({ score, className }: RiskGaugeProps) {
  const grade = getGrade(score)
  const color = getColor(score)
  const circumference = 2 * Math.PI * 90
  const strokeDashoffset = circumference - (score / 100) * circumference * 0.5

  return (
    <Card className={className}>
      <CardContent className="flex flex-col items-center justify-center p-6">
        <div className="relative">
          <svg width="200" height="100" className="transform rotate-180">
            {/* Background arc */}
            <path
              d="M 20 100 A 80 80 0 0 1 180 100"
              fill="none"
              stroke="#1c1c22"
              strokeWidth="20"
              strokeLinecap="round"
            />
            {/* Score arc */}
            <path
              d="M 20 100 A 80 80 0 0 1 180 100"
              fill="none"
              stroke={color}
              strokeWidth="20"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              className="transition-all duration-500"
            />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center">
              <div className="text-4xl font-bold" style={{ color }}>{grade}</div>
              <div className="text-sm text-muted-foreground">{score}/100</div>
            </div>
          </div>
        </div>
        <div className="mt-4 text-center">
          <div className="text-sm font-medium">Risk Score</div>
          <div className="text-xs text-muted-foreground">
            {score < 20 ? 'Low Risk' : score < 40 ? 'Moderate Risk' : score < 60 ? 'High Risk' : score < 80 ? 'Very High Risk' : 'Critical Risk'}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
