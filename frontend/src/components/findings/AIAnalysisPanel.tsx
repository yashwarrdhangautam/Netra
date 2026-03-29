import { useState } from 'react'
import { ChevronDown, ChevronUp, Brain, Target, FileText, UserX } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { cn } from '@/utils/formatters'

interface AIAnalysis {
  attacker?: {
    exploitability?: string
    business_impact?: string
    mitre_techniques?: string[]
    confidence?: number
  }
  defender?: {
    root_cause?: string
    immediate_fix?: string
    long_term_fix?: string
    priority?: string
    confidence?: number
  }
  analyst?: {
    framework_mappings?: Record<string, any[]>
    regulatory_risk?: string
    compliance_priority?: string
    confidence?: number
  }
  skeptic?: {
    verdict?: string
    reasoning?: string
    confidence?: number
  }
  consensus?: {
    status?: string
    final_confidence?: number
  }
}

interface AIAnalysisPanelProps {
  analysis: AIAnalysis
  className?: string
}

const TABS = [
  { id: 'attacker', label: 'Attacker', icon: Target },
  { id: 'defender', label: 'Defender', icon: Brain },
  { id: 'analyst', label: 'Analyst', icon: FileText },
  { id: 'skeptic', label: 'Skeptic', icon: UserX },
]

export function AIAnalysisPanel({ analysis, className }: AIAnalysisPanelProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [activeTab, setActiveTab] = useState('attacker')

  const consensus = analysis.consensus
  const activeData = analysis[activeTab as keyof typeof analysis]

  return (
    <Card className={className}>
      <div
        className="flex items-center justify-between p-4 cursor-pointer"
        onClick={() => setIsOpen(!isOpen)}
      >
        <div className="flex items-center gap-2">
          <Brain className="w-5 h-5 text-accent" />
          <span className="font-medium">AI Analysis</span>
          {consensus?.final_confidence && (
            <Badge variant="secondary">{consensus.final_confidence}% confidence</Badge>
          )}
        </div>
        {isOpen ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
      </div>

      {isOpen && (
        <CardContent>
          {/* Consensus verdict */}
          {consensus?.status && (
            <div className="mb-4 p-3 rounded-lg bg-surface-2 border border-border">
              <div className="text-sm font-medium">Consensus: {consensus.status.replace('_', ' ').toUpperCase()}</div>
              <div className="text-xs text-muted-foreground mt-1">
                Based on {Object.keys(analysis).filter(k => k !== 'consensus').length} persona analyses
              </div>
            </div>
          )}

          {/* Tabs */}
          <div className="flex gap-2 mb-4 border-b border-border">
            {TABS.map((tab) => {
              const Icon = tab.icon
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={cn(
                    'flex items-center gap-2 px-3 py-2 text-sm font-medium border-b-2 transition-colors',
                    activeTab === tab.id
                      ? 'border-accent text-accent'
                      : 'border-transparent text-muted-foreground hover:text-foreground'
                  )}
                >
                  <Icon className="w-4 h-4" />
                  {tab.label}
                </button>
              )
            })}
          </div>

          {/* Content */}
          <div className="space-y-3">
            {activeTab === 'attacker' && activeData && (
              <>
                <div>
                  <div className="text-sm font-medium">Exploitability</div>
                  <div className="text-sm text-muted-foreground">{(activeData as any).exploitability || 'N/A'}</div>
                </div>
                <div>
                  <div className="text-sm font-medium">Business Impact</div>
                  <div className="text-sm text-muted-foreground">{(activeData as any).business_impact || 'N/A'}</div>
                </div>
              </>
            )}

            {activeTab === 'defender' && activeData && (
              <>
                <div>
                  <div className="text-sm font-medium">Immediate Fix</div>
                  <div className="text-sm text-muted-foreground">{(activeData as any).immediate_fix || 'N/A'}</div>
                </div>
                <div>
                  <div className="text-sm font-medium">Long-term Fix</div>
                  <div className="text-sm text-muted-foreground">{(activeData as any).long_term_fix || 'N/A'}</div>
                </div>
                <div>
                  <div className="text-sm font-medium">Priority</div>
                  <Badge variant="secondary">{(activeData as any).priority || 'N/A'}</Badge>
                </div>
              </>
            )}

            {activeTab === 'analyst' && activeData && (
              <>
                <div>
                  <div className="text-sm font-medium">Regulatory Risk</div>
                  <div className="text-sm text-muted-foreground">{(activeData as any).regulatory_risk || 'N/A'}</div>
                </div>
                <div>
                  <div className="text-sm font-medium">Compliance Priority</div>
                  <Badge variant="secondary">{(activeData as any).compliance_priority || 'N/A'}</Badge>
                </div>
              </>
            )}

            {activeTab === 'skeptic' && activeData && (
              <>
                <div>
                  <div className="text-sm font-medium">Verdict</div>
                  <Badge variant="secondary">{(activeData as any).verdict || 'N/A'}</Badge>
                </div>
                <div>
                  <div className="text-sm font-medium">Reasoning</div>
                  <div className="text-sm text-muted-foreground">{(activeData as any).reasoning || 'N/A'}</div>
                </div>
              </>
            )}
          </div>
        </CardContent>
      )}
    </Card>
  )
}
