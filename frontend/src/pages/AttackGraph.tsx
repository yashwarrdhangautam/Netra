import { useState, useEffect, useCallback } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { useQuery } from '@tanstack/react-query'
import { useParams } from '@tanstack/react-router'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import { LoadingSkeleton } from '@/components/shared/LoadingSkeleton'
import { EmptyState } from '@/components/shared/EmptyState'
import { findingsApi } from '@/api/findings'
import { scansApi } from '@/api/scans'
import type { Finding } from '@/types/findings'

interface GraphNode {
  id: string
  label: string
  severity: string
  confidence: number
  finding: Finding
}

interface GraphLink {
  source: string
  target: string
  label?: string
}

interface GraphData {
  nodes: GraphNode[]
  links: GraphLink[]
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

interface SelectedFinding {
  id: string
  title: string
  severity: string
  description: string
  evidence?: string
  confidence: number
}

export function AttackGraph(): JSX.Element {
  // Reachable from /attack-graph (no scan in the URL) and /scans/$scanId.
  const params = useParams({ strict: false }) as { scanId?: string }
  const [selectedNode, setSelectedNode] = useState<SelectedFinding | null>(null)
  const [filteredSeverities, setFilteredSeverities] = useState<Set<string>>(
    new Set(['critical', 'high', 'medium', 'low', 'info'])
  )
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], links: [] })
  const [zoom, setZoom] = useState<number>(1)

  // Without a scan in the URL, default to the most recent scan.
  const { data: scanList } = useQuery({
    queryKey: ['scans-for-attack-graph'],
    queryFn: () => scansApi.list({ page: 1, per_page: 20 }),
    enabled: !params.scanId,
  })
  const scanId = params.scanId ?? scanList?.items?.[0]?.id

  // Fetch findings for the selected scan. The API returns { items, total, ... }.
  const { data: findings, isLoading, isError } = useQuery({
    queryKey: ['findings', scanId],
    queryFn: async () => {
      const response = await findingsApi.list({ scan_id: scanId, per_page: 100 })
      return response.items
    },
    enabled: !!scanId,
  })

  // Build graph data from findings
  useEffect(() => {
    if (!findings || findings.length === 0) {
      setGraphData({ nodes: [], links: [] })
      return
    }

    const nodes: GraphNode[] = findings.map((finding: Finding) => ({
      id: finding.id,
      label: finding.title,
      severity: finding.severity || 'info',
      confidence: finding.confidence || 0.5,
      finding,
    }))

    const links: GraphLink[] = []
    const seenLinks = new Set<string>()

    // Build edges from attack chains
    findings.forEach((finding: Finding) => {
      if (
        finding.ai_analysis?.attacker?.attack_chains &&
        Array.isArray(finding.ai_analysis.attacker.attack_chains)
      ) {
        finding.ai_analysis.attacker.attack_chains.forEach((chain: { steps?: string[] }) => {
          if (chain.steps && Array.isArray(chain.steps)) {
            for (let i = 0; i < chain.steps.length - 1; i++) {
              const sourceId = chain.steps[i]
              const targetId = chain.steps[i + 1]
              const linkKey = `${sourceId}->${targetId}`

              if (!seenLinks.has(linkKey)) {
                links.push({
                  source: sourceId,
                  target: targetId,
                  label: 'attack chain',
                })
                seenLinks.add(linkKey)
              }
            }
          }
        })
      }
    })

    setGraphData({ nodes, links })
  }, [findings])

  // Filter nodes by severity
  const filteredNodes = graphData.nodes.filter((node) =>
    filteredSeverities.has(node.severity)
  )
  const filteredNodeIds = new Set(filteredNodes.map((n) => n.id))
  const visibleLinks = graphData.links.filter(
    (link) =>
      filteredNodeIds.has(String(link.source)) &&
      filteredNodeIds.has(String(link.target))
  )

  const handleNodeClick = useCallback((node: GraphNode) => {
    const evidenceLines = node.finding.evidence || []
    const evidenceSnippet =
      Array.isArray(evidenceLines) && evidenceLines.length > 0
        ? evidenceLines[0]
        : 'No evidence available'

    setSelectedNode({
      id: node.id,
      title: node.label,
      severity: node.severity,
      description: node.finding.description || 'No description available',
      evidence: evidenceSnippet,
      confidence: node.confidence,
    })
  }, [])

  const handleToggleSeverity = (severity: string): void => {
    const updated = new Set(filteredSeverities)
    if (updated.has(severity)) {
      updated.delete(severity)
    } else {
      updated.add(severity)
    }
    setFilteredSeverities(updated)
  }

  const handleResetLayout = (): void => {
    setZoom(1)
  }

  const handleZoom = (direction: 'in' | 'out'): void => {
    const newZoom = direction === 'in' ? zoom * 1.2 : zoom / 1.2
    setZoom(newZoom)
  }

  if (isLoading) {
    return (
      <div className="h-screen bg-[#09090b] p-6">
        <LoadingSkeleton />
      </div>
    )
  }

  if (isError) {
    return (
      <div className="h-screen bg-[#09090b] p-6">
        <EmptyState
          title="Error Loading Attack Graph"
          description="Failed to load findings data. Please try again later."
        />
      </div>
    )
  }

  if (!findings || findings.length === 0) {
    return (
      <div className="h-screen bg-[#09090b] p-6">
        <EmptyState
          title="No Findings"
          description="No findings available for this scan. Run a scan to generate findings."
        />
      </div>
    )
  }

  return (
    <div className="h-screen flex gap-6 bg-[#09090b] p-6">
      {/* Graph Canvas */}
      <div className="flex-1 flex flex-col">
        <Card className="flex-1 border border-zinc-800 bg-zinc-950 shadow-lg">
          <CardContent className="p-0 h-full relative">
            <ForceGraph2D
              graphData={{
                nodes: filteredNodes,
                links: visibleLinks,
              }}
              nodeColor={(node) => SEVERITY_COLORS[(node as GraphNode).severity] || '#6b7280'}
              nodeVal={(node) => 4 + (node as GraphNode).confidence * 6}
              nodeCanvasObject={(node, ctx) => {
                const n = node as GraphNode & { x: number; y: number }
                const size = 4 + n.confidence * 6
                ctx.fillStyle = SEVERITY_COLORS[n.severity] || '#6b7280'
                ctx.beginPath()
                ctx.arc(n.x, n.y, size, 0, 2 * Math.PI)
                ctx.fill()

                // Node border for emphasis
                ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)'
                ctx.lineWidth = 1.5
                ctx.stroke()

                // Label
                if (n.id === selectedNode?.id) {
                  ctx.fillStyle = '#ffffff'
                  ctx.font = 'bold 12px sans-serif'
                  const textWidth = ctx.measureText(n.label).width
                  ctx.fillText(
                    n.label,
                    n.x - textWidth / 2,
                    n.y - size - 8
                  )
                }
              }}
              nodePointerAreaPaint={(node, color, ctx) => {
                const n = node as GraphNode & { x: number; y: number }
                ctx.fillStyle = color
                const size = 4 + n.confidence * 6
                ctx.beginPath()
                ctx.arc(n.x, n.y, size * 1.5, 0, 2 * Math.PI)
                ctx.fill()
              }}
              linkColor={() => 'rgba(148, 163, 184, 0.3)'}
              linkWidth={1.5}
              onNodeClick={(node) => {
                handleNodeClick(node as GraphNode)
              }}
              backgroundColor="#09090b"
              width={typeof window !== 'undefined' ? window.innerWidth * 0.65 : 800}
              height={typeof window !== 'undefined' ? window.innerHeight - 48 : 600}
              warmupTicks={100}
              cooldownTicks={200}
            />

            {/* Zoom Controls */}
            <div className="absolute bottom-4 left-4 flex flex-col gap-2">
              <Button
                onClick={() => handleZoom('in')}
                size="sm"
                className="bg-zinc-800 hover:bg-zinc-700 text-white"
                aria-label="Zoom in"
              >
                +
              </Button>
              <Button
                onClick={() => handleZoom('out')}
                size="sm"
                className="bg-zinc-800 hover:bg-zinc-700 text-white"
                aria-label="Zoom out"
              >
                −
              </Button>
              <Button
                onClick={handleResetLayout}
                size="sm"
                className="bg-zinc-800 hover:bg-zinc-700 text-white text-xs"
                aria-label="Reset layout"
              >
                Reset
              </Button>
            </div>

            {/* Node Count Badge */}
            <div className="absolute top-4 left-4 bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2">
              <p className="text-xs text-zinc-400">
                {filteredNodes.length} of {graphData.nodes.length} findings
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Sidebar: Controls & Details */}
      <div className="w-80 flex flex-col gap-4">
        {/* Severity Filter */}
        <Card className="border border-zinc-800 bg-zinc-950 shadow-lg">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-zinc-100">
              Severity Filter
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {Object.keys(SEVERITY_COLORS)
              .sort((a, b) => SEVERITY_ORDER[a] - SEVERITY_ORDER[b])
              .map((severity) => (
                <label
                  key={severity}
                  className="flex items-center gap-2 cursor-pointer hover:bg-zinc-900 p-2 rounded transition"
                >
                  <input
                    type="checkbox"
                    checked={filteredSeverities.has(severity)}
                    onChange={() => handleToggleSeverity(severity)}
                    className="w-4 h-4 rounded border-zinc-600 bg-zinc-950 cursor-pointer"
                  />
                  <span className="text-sm text-zinc-300 capitalize flex items-center gap-2">
                    {severity}
                    <span
                      className="w-3 h-3 rounded-full"
                      style={{ backgroundColor: SEVERITY_COLORS[severity] }}
                      aria-hidden="true"
                    />
                  </span>
                </label>
              ))}
          </CardContent>
        </Card>

        {/* Selected Finding Details */}
        {selectedNode ? (
          <Card className="border border-zinc-800 bg-zinc-950 shadow-lg flex-1 flex flex-col">
            <CardHeader className="pb-3 border-b border-zinc-800">
              <div className="flex items-start justify-between gap-2">
                <CardTitle className="text-sm font-semibold text-zinc-100 flex-1">
                  Finding Details
                </CardTitle>
                <Button
                  onClick={() => setSelectedNode(null)}
                  size="sm"
                  variant="ghost"
                  className="h-6 w-6 p-0 text-zinc-500 hover:text-zinc-300"
                >
                  ✕
                </Button>
              </div>
            </CardHeader>
            <CardContent className="flex-1 flex flex-col gap-4 overflow-y-auto py-4">
              {/* Title */}
              <div>
                <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide mb-1">
                  Title
                </p>
                <p className="text-sm text-zinc-100">{selectedNode.title}</p>
              </div>

              {/* Severity & Confidence */}
              <div className="space-y-2">
                <div>
                  <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide mb-1">
                    Severity
                  </p>
                  <SeverityBadge severity={selectedNode.severity} />
                </div>
                <div>
                  <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide mb-1">
                    Confidence
                  </p>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-blue-500 to-purple-500"
                        style={{ width: `${selectedNode.confidence * 100}%` }}
                      />
                    </div>
                    <span className="text-xs text-zinc-400 min-w-[3rem]">
                      {Math.round(selectedNode.confidence * 100)}%
                    </span>
                  </div>
                </div>
              </div>

              {/* Description */}
              <div>
                <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide mb-1">
                  Description
                </p>
                <p className="text-sm text-zinc-300 leading-relaxed">
                  {selectedNode.description}
                </p>
              </div>

              {/* Evidence */}
              <div>
                <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide mb-1">
                  Evidence
                </p>
                <div className="bg-zinc-900 border border-zinc-800 rounded p-2 text-xs text-zinc-400 font-mono overflow-x-auto max-h-32 overflow-y-auto">
                  {selectedNode.evidence || 'No evidence available'}
                </div>
              </div>

              {/* Finding ID */}
              <div>
                <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide mb-1">
                  Finding ID
                </p>
                <p className="text-xs text-zinc-500 font-mono break-all">
                  {selectedNode.id}
                </p>
              </div>
            </CardContent>
          </Card>
        ) : (
          <Card className="border border-zinc-800 bg-zinc-950 shadow-lg flex items-center justify-center p-6 min-h-[300px]">
            <p className="text-sm text-zinc-500 text-center">
              Click a node to view finding details
            </p>
          </Card>
        )}

        {/* Legend */}
        <Card className="border border-zinc-800 bg-zinc-950 shadow-lg">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-zinc-100">
              Legend
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-xs text-zinc-400">
            <p>
              <span className="font-semibold">Node size:</span> Finding confidence
            </p>
            <p>
              <span className="font-semibold">Node color:</span> Severity level
            </p>
            <p>
              <span className="font-semibold">Edge:</span> Attack chain connection
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
