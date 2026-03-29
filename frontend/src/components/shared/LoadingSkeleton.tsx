import { cn } from '@/utils/formatters'

interface LoadingSkeletonProps {
  variant?: 'card' | 'table' | 'chart' | 'text'
  className?: string
}

export function LoadingSkeleton({ variant = 'card', className }: LoadingSkeletonProps) {
  if (variant === 'card') {
    return (
      <div className={cn('rounded-lg border border-border bg-surface p-6', className)}>
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-surface-2 rounded w-1/4" />
          <div className="h-8 bg-surface-2 rounded w-3/4" />
          <div className="h-4 bg-surface-2 rounded w-1/2" />
        </div>
      </div>
    )
  }

  if (variant === 'table') {
    return (
      <div className={cn('space-y-4', className)}>
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="animate-pulse flex gap-4">
            <div className="h-10 bg-surface-2 rounded flex-1" />
            <div className="h-10 bg-surface-2 rounded flex-1" />
            <div className="h-10 bg-surface-2 rounded flex-1" />
          </div>
        ))}
      </div>
    )
  }

  if (variant === 'chart') {
    return (
      <div className={cn('rounded-lg border border-border bg-surface p-6 h-64', className)}>
        <div className="animate-pulse h-full flex items-center justify-center">
          <div className="h-32 w-32 rounded-full bg-surface-2" />
        </div>
      </div>
    )
  }

  // Text variant
  return (
    <div className={cn('space-y-2', className)}>
      {Array.from({ length: 3 }).map((_, i) => (
        <div key={i} className="animate-pulse h-4 bg-surface-2 rounded" />
      ))}
    </div>
  )
}
