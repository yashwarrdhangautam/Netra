import React from 'react'
import { cn } from '@/utils/formatters'

interface TableProps {
  children: React.ReactNode
  className?: string
  colSpan?: number
  onClick?: () => void
}

export function Table({ children, className }: TableProps) {
  return (
    <div className="w-full overflow-auto">
      <table className={cn('w-full text-sm', className)}>
        {children}
      </table>
    </div>
  )
}

export function TableHeader({ children }: TableProps) {
  return <thead className="bg-surface-2">{children}</thead>
}

export function TableBody({ children }: TableProps) {
  return <tbody>{children}</tbody>
}

export function TableRow({ children, className }: TableProps) {
  return (
    <tr className={cn('border-b border-border hover:bg-surface-2/50', className)}>
      {children}
    </tr>
  )
}

export function TableHead({ children, className, colSpan, onClick }: TableProps) {
  return (
    <th className={cn('h-10 px-4 text-left font-medium text-muted-foreground', className)} colSpan={colSpan} onClick={onClick}>
      {children}
    </th>
  )
}

export function TableCell({ children, className, colSpan }: TableProps) {
  return (
    <td className={cn('px-4 py-3 text-foreground', className)} colSpan={colSpan}>
      {children}
    </td>
  )
}
