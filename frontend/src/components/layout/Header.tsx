import { Bell, Plus, HelpCircle, Menu, Square } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { useAuthStore } from '@/stores/authStore'
import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { bugBountyApi } from '@/api/bugbounty'

interface HeaderProps {
  onMenuClick?: () => void
}

export function Header({ onMenuClick }: HeaderProps) {
  const { user } = useAuthStore()
  const [showMobileMenu, setShowMobileMenu] = useState(false)
  const [killConfirm, setKillConfirm] = useState('')
  const [showKillConfirm, setShowKillConfirm] = useState(false)
  const killSwitch = useMutation({
    mutationFn: () => bugBountyApi.killSwitch(killConfirm),
    onSuccess: () => {
      setShowKillConfirm(false)
      setKillConfirm('')
    },
  })

  const handleOpenShortcuts = () => {
    window.dispatchEvent(new CustomEvent('netra:show-shortcuts'))
  }

  return (
    <>
      <header className="flex h-16 items-center justify-between border-b border-border bg-surface px-4 md:px-6">
        {/* Mobile Menu Button */}
        <button
          onClick={onMenuClick}
          className="md:hidden p-2 text-muted-foreground hover:bg-surface-2 rounded-md"
          aria-label="Toggle menu"
        >
          <Menu className="h-5 w-5" />
        </button>

        {/* Left side - Page title would go here */}
        <div className="flex-1" />

        {/* Right side - Actions */}
        <div className="flex items-center space-x-2 md:space-x-4">
          {/* Keyboard Shortcuts Help */}
          <button
            onClick={handleOpenShortcuts}
            className="hidden md:block rounded-full p-2 text-muted-foreground hover:bg-surface-2 hover:text-foreground transition-colors"
            title="Keyboard shortcuts (?)"
            aria-label="Show keyboard shortcuts"
          >
            <HelpCircle className="h-5 w-5" />
          </button>

          {/* Notifications */}
          <button
            className="relative rounded-full p-2 text-muted-foreground hover:bg-surface-2 hover:text-foreground"
            aria-label="View notifications"
          >
            <Bell className="h-5 w-5" />
            <span className="absolute right-2 top-2 h-2 w-2 rounded-full bg-accent" />
          </button>

          {/* New Scan Button */}
          <Button 
            size="sm" 
            onClick={() => window.dispatchEvent(new CustomEvent('netra:new-scan'))}
            className="hidden md:inline-flex"
          >
            <Plus className="h-4 w-4 md:mr-2" />
            <span className="hidden md:inline">New Scan</span>
          </Button>

          {/* Mobile FAB */}
          <Button
            size="sm"
            onClick={() => window.dispatchEvent(new CustomEvent('netra:new-scan'))}
            className="md:hidden h-10 w-10 rounded-full p-0"
            aria-label="New Scan"
          >
            <Plus className="h-5 w-5" />
          </Button>

          <Button
            size="sm"
            variant="outline"
            onClick={() => setShowKillConfirm(true)}
            className="border-red-900 text-red-300 hover:bg-red-950/40"
          >
            <Square className="h-4 w-4 md:mr-2" />
            <span className="hidden md:inline">Kill</span>
          </Button>

          {/* User */}
          <div className="flex items-center space-x-2 md:space-x-3">
            <div className="h-8 w-8 rounded-full bg-accent flex items-center justify-center text-sm font-medium">
              {user?.email?.[0].toUpperCase() || 'U'}
            </div>
            <span className="hidden md:block text-sm text-muted-foreground">{user?.email || 'User'}</span>
          </div>
        </div>
      </header>

      {/* Mobile Menu Overlay */}
      {showMobileMenu && (
        <div 
          className="fixed inset-0 z-50 bg-black/50 md:hidden"
          onClick={() => setShowMobileMenu(false)}
        >
          <div 
            className="absolute left-0 top-0 h-full w-64 bg-surface border-r border-border"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Mobile menu content would go here */}
            <div className="p-4 border-b border-border">
              <h2 className="text-lg font-semibold">Menu</h2>
            </div>
            <nav className="p-4 space-y-2">
              <a href="/" className="block p-2 rounded hover:bg-surface-2">Dashboard</a>
              <a href="/scans" className="block p-2 rounded hover:bg-surface-2">Scans</a>
              <a href="/findings" className="block p-2 rounded hover:bg-surface-2">Findings</a>
              <a href="/reports" className="block p-2 rounded hover:bg-surface-2">Reports</a>
              <a href="/settings" className="block p-2 rounded hover:bg-surface-2">Settings</a>
            </nav>
          </div>
        </div>
      )}

      {showKillConfirm ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
          <div className="w-full max-w-sm rounded border border-red-900 bg-surface p-4">
            <h2 className="text-lg font-semibold text-red-300">Kill switch</h2>
            <p className="mt-2 text-sm text-muted-foreground">Type STOP to cancel all active NETRA-BB hunts.</p>
            <input
              value={killConfirm}
              onChange={(event) => setKillConfirm(event.target.value)}
              className="mt-3 w-full rounded border border-border bg-surface-2 px-3 py-2 font-mono text-sm"
            />
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setShowKillConfirm(false)}>Cancel</Button>
              <Button variant="destructive" disabled={killConfirm !== 'STOP' || killSwitch.isPending} onClick={() => killSwitch.mutate()}>
                Stop hunts
              </Button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  )
}
