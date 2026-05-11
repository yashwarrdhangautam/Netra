import { useState } from 'react'
import { Check, Terminal } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'

interface CopyCurlButtonProps {
  findingId: string
  variant?: 'default' | 'outline' | 'ghost'
  size?: 'sm' | 'md' | 'lg'
}

export function CopyCurlButton({
  findingId,
  variant = 'outline',
  size = 'sm',
}: CopyCurlButtonProps) {
  const [copied, setCopied] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [curlCommand, setCurlCommand] = useState<string | null>(null)

  const handleCopy = async () => {
    setLoading(true)
    setError(null)

    try {
      // Fetch cURL command from API
      const token = localStorage.getItem('netra_token')
      const response = await fetch(
        `http://localhost:8000/api/v1/findings/${findingId}/curl`,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        }
      )

      if (!response.ok) {
        if (response.status === 404) {
          throw new Error('Finding not found')
        }
        throw new Error('Failed to fetch cURL command')
      }

      const data = await response.json()
      const curlCommand = data.curl_command

      // Copy to clipboard
      await navigator.clipboard.writeText(curlCommand)
      setCurlCommand(curlCommand)
      setCopied(true)

      // Reset copied state after 2 seconds
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to copy')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex items-center gap-2">
      <Button
        variant={variant}
        size={size}
        onClick={handleCopy}
        disabled={loading}
        title="Copy as cURL command"
      >
        {loading ? (
          <span className="animate-spin">⏳</span>
        ) : copied ? (
          <Check className="h-4 w-4 text-green-500" />
        ) : (
          <Terminal className="h-4 w-4" />
        )}
        {copied ? 'Copied!' : 'Copy as cURL'}
      </Button>

      {/* Show preview on hover */}
      {curlCommand && !copied && (
        <div className="relative group">
          <Badge variant="outline" className="cursor-help">
            <Terminal className="h-3 w-3 mr-1" />
            cURL available
          </Badge>
          <div className="absolute bottom-full left-0 mb-2 hidden w-96 group-hover:block">
            <div className="rounded-md border border-border bg-surface p-2 text-xs font-mono text-muted-foreground shadow-lg">
              <code className="break-all">{curlCommand}</code>
            </div>
          </div>
        </div>
      )}

      {error && (
        <Badge variant="destructive" className="text-xs">
          {error}
        </Badge>
      )}
    </div>
  )
}
