import { Link, useNavigate } from '@tanstack/react-router'
import {
  LayoutDashboard,
  Scan,
  FileText,
  ShieldCheck,
  Target,
  Network,
  Settings,
  Bug,
  LogOut,
  Users,
  ShieldAlert,
  Activity,
  FileSearch,
  ClipboardList,
  Stethoscope,
  AlertCircle,
  GitBranch,
  CalendarClock,
  ScrollText,
  SlidersHorizontal,
} from 'lucide-react'
import { useAuthStore } from '@/stores/authStore'
import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import { accountApi } from '@/api/platform'
import { cn } from '@/utils/formatters'

interface NavItem {
  name: string
  href: string
  icon: typeof Scan
  adminOnly?: boolean
}

const navigation: NavItem[] = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Scans', href: '/scans', icon: Scan },
  { name: 'Schedules', href: '/schedules', icon: CalendarClock },
  { name: 'Findings', href: '/findings', icon: Bug },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Compliance', href: '/compliance', icon: ShieldCheck },
  { name: 'Targets', href: '/targets', icon: Target },
  { name: 'Attack Graph', href: '/attack-graph', icon: Network },
  { name: 'Users', href: '/users', icon: Users, adminOnly: true },
  { name: 'Audit log', href: '/audit', icon: ScrollText, adminOnly: true },
  { name: 'Settings', href: '/settings', icon: Settings },
  { name: 'BB Console', href: '/bb', icon: ShieldCheck },
  { name: 'BB Programs', href: '/bb/programs', icon: ClipboardList },
  { name: 'BB Scope', href: '/bb/scope', icon: ShieldAlert },
  { name: 'BB Hunts', href: '/bb/hunts', icon: Activity },
  { name: 'BB Triage', href: '/bb/triage', icon: FileSearch },
  { name: 'BB Submissions', href: '/bb/submissions', icon: FileText },
  { name: 'BB Graph', href: '/bb/graph', icon: GitBranch },
  { name: 'BB Audit', href: '/bb/audit', icon: AlertCircle },
  { name: 'BB Doctor', href: '/bb/doctor', icon: Stethoscope },
  { name: 'BB Settings', href: '/bb/settings', icon: SlidersHorizontal, adminOnly: true },
]

export function Sidebar() {
  const { logout, isAdmin } = useAuthStore()
  const navigate = useNavigate()
  // Bug bounty entries only show when the server has the module enabled (NETRA_BB_ENABLED).
  const { data: features } = useQuery({
    queryKey: ['features'],
    queryFn: async () => (await apiClient.get<{ bugbounty: boolean }>('/api/v1/features')).data,
    staleTime: 60_000,
  })
  const bugbountyOn = features?.bugbounty ?? true

  const handleLogout = async (): Promise<void> => {
    await accountApi.logout()
    logout()
    await navigate({ to: '/login' })
  }

  return (
    <div className="flex h-full w-64 flex-col border-r border-border bg-surface">
      {/* Logo */}
      <div className="flex h-16 items-center border-b border-border px-6">
        <span className="text-xl font-bold text-accent">NETRA</span>
        <span className="ml-2 text-xs text-muted-foreground">नेत्र</span>
      </div>
      <p className="border-b border-border px-6 py-2 text-xs text-muted-foreground">
        The Third Eye of Security
      </p>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4">
        {navigation
          .filter((item) => !item.adminOnly || isAdmin())
          .filter((item) => bugbountyOn || !item.href.startsWith('/bb'))
          .map((item) => (
            <Link key={item.name} to={item.href}>
              {({ isActive }) => (
                <span
                  className={cn(
                    'group flex items-center rounded-md px-3 py-2 text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-accent text-white'
                      : 'text-muted-foreground hover:bg-surface-2 hover:text-foreground'
                  )}
                >
                  <item.icon className="mr-3 h-5 w-5" />
                  {item.name}
                </span>
              )}
            </Link>
          ))}
      </nav>

      {/* Logout */}
      <div className="border-t border-border p-3">
        <button
          onClick={handleLogout}
          className="flex w-full items-center rounded-md px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-surface-2 hover:text-foreground"
        >
          <LogOut className="mr-3 h-5 w-5" />
          Logout
        </button>
      </div>
    </div>
  )
}
