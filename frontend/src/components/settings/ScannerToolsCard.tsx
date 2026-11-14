import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { scannerApi, type ScannerToolRow } from '@/api/platform'

function Row({ tool }: { tool: ScannerToolRow }) {
  const state = tool.installed ? 'Installed' : tool.optional ? 'Optional, missing' : 'Missing'
  const tone = tool.installed
    ? 'text-emerald-600'
    : tool.optional
      ? 'text-muted-foreground'
      : 'text-red-600'
  return (
    <li className="flex flex-wrap items-baseline justify-between gap-2 border-b py-2 last:border-0">
      <span className="font-medium">{tool.label}</span>
      <span className={`text-xs ${tone}`}>{state}</span>
      {!tool.installed && (
        <span className="w-full text-xs text-muted-foreground">{tool.install_hint}</span>
      )}
    </li>
  )
}

export function ScannerToolsCard() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scanner-tools'],
    queryFn: scannerApi.tools,
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>Scanner tools</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        {isLoading && <p className="text-muted-foreground">Checking tools...</p>}
        {isError && <p className="text-red-600">Could not load the tool list.</p>}
        {data && (
          <>
            <p className={data.missing_count > 0 ? 'text-red-600' : 'text-emerald-600'}>
              {data.missing_count > 0
                ? `${data.missing_count} required tool(s) missing: ${data.missing_required.join(', ')}. Scans that use them will record a failure for that tool.`
                : 'All required tools are installed.'}
            </p>
            <ul>
              {data.tools.map((tool) => (
                <Row key={tool.binary} tool={tool} />
              ))}
            </ul>
          </>
        )}
      </CardContent>
    </Card>
  )
}
