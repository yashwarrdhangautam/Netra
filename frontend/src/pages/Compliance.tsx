import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'

const frameworks = [
  { id: 'iso27001', name: 'ISO 27001' },
  { id: 'pci_dss', name: 'PCI DSS' },
  { id: 'soc2', name: 'SOC 2' },
  { id: 'hipaa', name: 'HIPAA' },
  { id: 'nist_csf', name: 'NIST CSF' },
  { id: 'cis', name: 'CIS Controls' },
]

export function Compliance() {
  const [selectedFramework, setSelectedFramework] = useState('iso27001')

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Compliance</h1>

      <div className="flex space-x-2">
        {frameworks.map((fw) => (
          <Button
            key={fw.id}
            variant={selectedFramework === fw.id ? 'default' : 'outline'}
            size="sm"
            onClick={() => setSelectedFramework(fw.id)}
          >
            {fw.name}
          </Button>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{frameworks.find(f => f.id === selectedFramework)?.name} Compliance</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-muted-foreground">
            Select a scan to view compliance score and gap analysis.
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
