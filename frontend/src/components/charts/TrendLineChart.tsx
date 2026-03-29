import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'

interface TrendData {
  date: string
  critical: number
  high: number
  medium: number
  low: number
}

interface TrendLineChartProps {
  data: TrendData[]
  className?: string
}

export function TrendLineChart({ data, className }: TrendLineChartProps) {
  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>Findings Trend</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1c1c22" />
            <XAxis dataKey="date" stroke="#8b949e" fontSize={12} />
            <YAxis stroke="#8b949e" fontSize={12} />
            <Tooltip
              contentStyle={{
                backgroundColor: '#0c0c0f',
                border: '1px solid #1c1c22',
                borderRadius: '6px',
              }}
            />
            <Legend />
            <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="medium" stroke="#f59e0b" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="low" stroke="#3b82f6" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  )
}
