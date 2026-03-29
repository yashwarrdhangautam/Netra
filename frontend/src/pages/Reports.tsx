import { useState } from 'react'
import { reportsApi, type ReportType } from '@/api/reports'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'

const reportTypes: { value: ReportType; label: string; description: string }[] = [
  { value: 'executive', label: 'Executive', description: '1-page PDF summary for leadership' },
  { value: 'technical', label: 'Technical', description: 'Detailed Word document' },
  { value: 'pentest', label: 'Pentest', description: 'Professional pentest deliverable' },
  { value: 'html', label: 'HTML', description: 'Interactive dashboard' },
  { value: 'excel', label: 'Excel', description: '9-sheet workbook' },
  { value: 'evidence', label: 'Evidence', description: 'ZIP with SHA256 chain of custody' },
  { value: 'compliance', label: 'Compliance', description: 'Framework gap analysis' },
  { value: 'full', label: 'Full', description: 'Comprehensive combined report' },
]

export function Reports() {
  const [selectedType, setSelectedType] = useState<ReportType>('executive')
  const [isGenerating, setIsGenerating] = useState(false)

  const handleGenerate = async () => {
    setIsGenerating(true)
    try {
      // In real app, would need scan selection
      await reportsApi.generate('scan-id-placeholder', selectedType)
    } catch (error) {
      console.error('Failed to generate report:', error)
    } finally {
      setIsGenerating(false)
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Reports</h1>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {reportTypes.map((type) => (
          <Card
            key={type.value}
            className={`cursor-pointer transition-colors ${
              selectedType === type.value ? 'border-accent bg-surface-2' : ''
            }`}
            onClick={() => setSelectedType(type.value)}
          >
            <CardHeader>
              <CardTitle className="text-base">{type.label}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">{type.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Generate Report</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-4 text-sm text-muted-foreground">
            Selected: <span className="font-medium">{reportTypes.find(t => t.value === selectedType)?.label}</span>
          </p>
          <Button onClick={handleGenerate} disabled={isGenerating}>
            {isGenerating ? 'Generating...' : 'Generate Report'}
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
