import { cn } from '@/utils/formatters'

interface SkeletonProps {
  className?: string
}

export function Skeleton({ className }: SkeletonProps) {
  return (
    <div
      className={cn(
        'animate-pulse rounded-md bg-surface-2',
        className
      )}
    />
  )
}
