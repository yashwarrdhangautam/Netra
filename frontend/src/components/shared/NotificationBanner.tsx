import { useEffect } from 'react'
import { CheckCircle2, AlertTriangle, X } from 'lucide-react'
import { cn } from '@/utils/formatters'

export interface BannerMessage {
  type: 'success' | 'error' | 'info'
  text: string
}

interface NotificationBannerProps {
  message: BannerMessage | null
  onDismiss: () => void
  autoHideMs?: number
}

/** Inline status message for a form or action. Announced to screen readers. */
export function NotificationBanner({ message, onDismiss, autoHideMs = 6000 }: NotificationBannerProps) {
  useEffect(() => {
    if (!message || autoHideMs <= 0) return
    const timer = window.setTimeout(onDismiss, autoHideMs)
    return () => window.clearTimeout(timer)
  }, [message, autoHideMs, onDismiss])

  if (!message) return null

  const Icon = message.type === 'success' ? CheckCircle2 : AlertTriangle
  return (
    <div
      role={message.type === 'error' ? 'alert' : 'status'}
      className={cn(
        'flex items-start justify-between gap-3 rounded-md border px-4 py-3 text-sm',
        message.type === 'success' && 'border-green-700 bg-green-900/20 text-green-300',
        message.type === 'error' && 'border-red-700 bg-red-900/20 text-red-300',
        message.type === 'info' && 'border-border bg-surface-2 text-foreground'
      )}
    >
      <span className="flex items-start gap-2">
        <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
        {message.text}
      </span>
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss message"
        className="rounded p-1 hover:bg-surface"
      >
        <X className="h-4 w-4" aria-hidden="true" />
      </button>
    </div>
  )
}
