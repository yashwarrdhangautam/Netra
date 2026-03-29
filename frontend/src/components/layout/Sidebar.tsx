import { NavLink } from '@tanstack/react-router'
import { 
  LayoutDashboard, 
  Scan, 
  FileText, 
  ShieldCheck, 
  Target, 
  Network, 
  Settings,
  Bug,
  LogOut
} from 'lucide-react'
import { useAuthStore } from '@/stores/authStore'
import { cn } from '@/utils/formatters'

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Scans', href: '/scans', icon: Scan },
  { name: 'Findings', href: '/findings', icon: Bug },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Compliance', href: '/compliance', icon: ShieldCheck },
  { name: 'Targets', href: '/targets', icon: Target },
  { name: 'Attack Graph', href: '/attack-graph', icon: Network },
  { name: 'Settings', href: '/settings', icon: Settings },
]

export function Sidebar() {
  const { logout } = useAuthStore()

  return (
    <div className="flex h-full w-64 flex-col border-r border-border bg-surface">
      {/* Logo */}
      <div className="flex h-16 items-center border-b border-border px-6">
        <span className="text-xl font-bold text-accent">NETRA</span>
        <span className="ml-2 text-xs text-muted-foreground">नेत्र</span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 px-3 py-4">
        {navigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.href}
            className={({ isActive }) =>
              cn(
                'group flex items-center rounded-md px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-accent text-white'
                  : 'text-muted-foreground hover:bg-surface-2 hover:text-foreground'
              )
            }
          >
            <item.icon className="mr-3 h-5 w-5" />
            {item.name}
          </NavLink>
        ))}
      </nav>

      {/* Logout */}
      <div className="border-t border-border p-3">
        <button
          onClick={logout}
          className="flex w-full items-center rounded-md px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-surface-2 hover:text-foreground"
        >
          <LogOut className="mr-3 h-5 w-5" />
          Logout
        </button>
      </div>
    </div>
  )
}
