import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import axios from 'axios'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table'
import { ArrowLeftRight, TrendingUp, TrendingDown, Minus, Download, AlertCircle } from 'lucide-react'
import type { Scan } from '@/types'

interface ScanComparison {
  scan_a: Scan
  scan_b: Scan
  new_findings: number
  resolved_findings: number
  changed_findings: number
  unchanged_findings: number
  diff_data: {
    scan_a_total: number
    scan_b_total: number
    new_finding_ids: string[]
    resolved_finding_ids: string[]
  }
}

export function ScanCompare() {
  const navigate = useNavigate()
  const [scanAId, setScanAId] = useState<string>('')
  const [scanBId, setScanBId] = useState<string>('')
  const [comparison, setComparison] = useState<ScanComparison | null>(null)

  const API_BASE = import.meta.env?.VITE_API_URL || 'http://localhost:8000'

  const getAuthHeaders = () => {
    // Cookies are sent automatically with credentials: include
    return {
      headers: {
        'Content-Type': 'application/json',
      },
    }
  }

  // Fetch all scans for selection
  const { data: scans = [] } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const response = await axios.get(`${API_BASE}/api/v1/scans`, getAuthHeaders())
      return response.data.data || []
    },
  })

  // Compare mutation
  const compareMutation = useMutation({
    mutationFn: async () => {
      const response = await axios.post(
        `${API_BASE}/api/v1/scans/compare`,
        { scan_a_id: scanAId, scan_b_id: scanBId },
        getAuthHeaders()
      )
      return response.data
    },
    onSuccess: (data: ScanComparison) => {
      setComparison(data)
    },
  })

  const handleCompare = () => {
    if (!scanAId || !scanBId) return
    compareMutation.mutate()
  }

  const handleExportPDF = () => {
    // TODO: Implement PDF export
    alert('PDF export coming soon!')
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate({ to: '/scans' })}
          >
            <ArrowLeftRight className="h-4 w-4 mr-2" />
            Back to Scans
          </Button>
          <div>
            <h1 className="text-2xl font-bold text-foreground">Scan Comparison</h1>
            <p className="text-muted-foreground">Compare two scans to identify changes</p>
          </div>
        </div>
        {comparison && (
          <Button onClick={handleExportPDF} variant="outline" size="sm">
            <Download className="h-4 w-4 mr-2" />
            Export PDF
          </Button>
        )}
      </div>

      {/* Scan Selection */}
      <Card>
        <CardHeader>
          <CardTitle>Select Scans to Compare</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <label className="text-sm font-medium">Scan A (Baseline)</label>
              <select
                value={scanAId}
                onChange={(e) => setScanAId(e.target.value)}
                className="w-full rounded-md border border-border bg-surface px-3 py-2 text-sm"
              >
                <option value="">Select scan...</option>
                {scans.map((scan: Scan) => (
                  <option key={scan.id} value={scan.id}>
                    {scan.name} - {new Date(scan.created_at).toLocaleDateString()}
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Scan B (Comparison)</label>
              <select
                value={scanBId}
                onChange={(e) => setScanBId(e.target.value)}
                className="w-full rounded-md border border-border bg-surface px-3 py-2 text-sm"
              >
                <option value="">Select scan...</option>
                {scans.map((scan: Scan) => (
                  <option key={scan.id} value={scan.id}>
                    {scan.name} - {new Date(scan.created_at).toLocaleDateString()}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="mt-4 flex justify-end">
            <Button
              onClick={handleCompare}
              disabled={!scanAId || !scanBId || compareMutation.isPending}
            >
              <ArrowLeftRight className="h-4 w-4 mr-2" />
              {compareMutation.isPending ? 'Comparing...' : 'Compare Scans'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Comparison Results */}
      {comparison && (
        <>
          {/* Summary Stats */}
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center gap-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-500/20">
                    <TrendingUp className="h-6 w-6 text-green-500" />
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">New Findings</p>
                    <p className="text-2xl font-bold text-green-500">
                      {comparison.new_findings}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center gap-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-500/20">
                    <TrendingDown className="h-6 w-6 text-red-500" />
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Resolved Findings</p>
                    <p className="text-2xl font-bold text-red-500">
                      {comparison.resolved_findings}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center gap-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-full bg-yellow-500/20">
                    <AlertCircle className="h-6 w-6 text-yellow-500" />
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Changed Findings</p>
                    <p className="text-2xl font-bold text-yellow-500">
                      {comparison.changed_findings}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center gap-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-full bg-blue-500/20">
                    <Minus className="h-6 w-6 text-blue-500" />
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Unchanged</p>
                    <p className="text-2xl font-bold text-blue-500">
                      {comparison.unchanged_findings}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Detailed Comparison Table */}
          <Card>
            <CardHeader>
              <CardTitle>Detailed Comparison</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Finding</TableHead>
                    <TableHead>Scan A Status</TableHead>
                    <TableHead>Scan B Status</TableHead>
                    <TableHead>Change</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {/* New Findings */}
                  {comparison.diff_data.new_finding_ids.slice(0, 10).map((findingId: string) => (
                    <TableRow key={findingId}>
                      <TableCell className="font-medium">{findingId}</TableCell>
                      <TableCell>-</TableCell>
                      <TableCell>
                        <Badge variant="default" className="bg-green-500/20 text-green-500">
                          New
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="default" className="bg-green-500/20 text-green-500">
                          + New
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}

                  {/* Resolved Findings */}
                  {comparison.diff_data.resolved_finding_ids.slice(0, 10).map((findingId: string) => (
                    <TableRow key={findingId}>
                      <TableCell className="font-medium">{findingId}</TableCell>
                      <TableCell>
                        <Badge variant="default" className="bg-red-500/20 text-red-500">
                          Found
                        </Badge>
                      </TableCell>
                      <TableCell>-</TableCell>
                      <TableCell>
                        <Badge variant="default" className="bg-red-500/20 text-red-500">
                          - Resolved
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              {(comparison.new_findings > 10 || comparison.resolved_findings > 10) && (
                <p className="mt-4 text-sm text-muted-foreground">
                  Showing first 10 findings. Export PDF for full report.
                </p>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}
