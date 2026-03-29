import { Bell, Plus } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { useAuthStore } from '@/stores/authStore'

export function Header() {
  const { user } = useAuthStore()

  return (
    <header className="flex h-16 items-center justify-between border-b border-border bg-surface px-6">
      {/* Left side - Page title would go here */}
      <div className="flex-1" />

      {/* Right side - Actions */}
      <div className="flex items-center space-x-4">
        {/* New Scan Button */}
        <Button size="sm">
          <Plus className="mr-2 h-4 w-4" />
          New Scan
        </Button>

        {/* Notifications */}
        <button className="relative rounded-full p-2 text-muted-foreground hover:bg-surface-2 hover:text-foreground">
          <Bell className="h-5 w-5" />
          <span className="absolute right-2 top-2 h-2 w-2 rounded-full bg-accent" />
        </button>

        {/* User */}
        <div className="flex items-center space-x-3">
          <div className="h-8 w-8 rounded-full bg-accent flex items-center justify-center text-sm font-medium">
            {user?.email?.[0].toUpperCase() || 'U'}
          </div>
          <span className="text-sm text-muted-foreground">{user?.email || 'User'}</span>
        </div>
      </div>
    </header>
  )
}
