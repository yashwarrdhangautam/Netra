import React from 'react'
import { cn } from '@/utils/formatters'

interface BadgeProps {
  children: React.ReactNode
  variant?: 'default' | 'secondary' | 'outline' | 'destructive' | 'accent' | 'ghost'
  className?: string
}

export function Badge({ children, variant = 'default', className }: BadgeProps) {
  const variants = {
    default: 'bg-accent text-white',
    secondary: 'bg-surface-2 text-foreground',
    outline: 'border border-border text-foreground',
    destructive: 'bg-red-600 text-white',
    accent: 'bg-accent-2 text-white',
    ghost: 'bg-transparent text-muted-foreground',
  }

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md px-2 py-1 text-xs font-medium',
        variants[variant],
        className
      )}
    >
      {children}
    </span>
  )
}
