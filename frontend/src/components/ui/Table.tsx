import { cn } from '@/utils/formatters'

interface TableProps {
  children: React.ReactNode
  className?: string
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

export function TableHead({ children, className }: TableProps) {
  return (
    <th className={cn('h-10 px-4 text-left font-medium text-muted-foreground', className)}>
      {children}
    </th>
  )
}

export function TableCell({ children, className }: TableProps) {
  return (
    <td className={cn('px-4 py-3', className)}>
      {children}
    </td>
  )
}
