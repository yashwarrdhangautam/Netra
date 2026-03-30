import React from 'react'
import { cn } from '@/utils/formatters'

interface CardProps {
  children: React.ReactNode
  className?: string
  onClick?: () => void
}

export function Card({ children, className, onClick }: CardProps) {
  return (
    <div
      className={cn(
        'rounded-lg border border-border bg-surface p-6',
        className
      )}
      onClick={onClick}
    >
      {children}
    </div>
  )
}

export function CardHeader({ children, className }: CardProps) {
  return <div className={cn('mb-4', className)}>{children}</div>
}

export function CardTitle({ children, className }: CardProps) {
  return <h3 className={cn('text-lg font-semibold', className)}>{children}</h3>
}

export function CardContent({ children, className }: CardProps) {
  return <div className={cn('', className)}>{children}</div>
}
