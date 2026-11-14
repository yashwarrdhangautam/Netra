import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts'
import { useFaviconStatus } from '@/hooks/useFaviconStatus'
import { useEffect, useState } from 'react'
import { KeyboardShortcutsModal } from '@/components/shared/KeyboardShortcutsModal'

interface LayoutProps {
  children: React.ReactNode
}

export function Layout({ children }: LayoutProps) {
  const [showShortcutsModal, setShowShortcutsModal] = useState(false)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [scanStatus, setScanStatus] = useState<'idle' | 'scanning' | 'complete' | 'success'>('idle')

  // Initialize global keyboard shortcuts
  useKeyboardShortcuts({
    onShowHelp: () => setShowShortcutsModal(true),
  })

  // Initialize favicon status
  const { setFaviconStatus, requestNotificationPermission } = useFaviconStatus({
    status: scanStatus,
    enabled: true,
  })

  // Request notification permission on mount
  useEffect(() => {
    requestNotificationPermission()
  }, [requestNotificationPermission])

  // Listen for scan status changes from WebSocket or events
  useEffect(() => {
    const handleScanStart = () => {
      setScanStatus('scanning')
      setFaviconStatus('scanning')
    }

    const handleScanComplete = () => {
      setScanStatus('complete')
      setFaviconStatus('complete')
      
      if (Notification.permission === 'granted') {
        new Notification('Scan Complete', {
          body: 'Your security scan has completed.',
          icon: '/favicon.svg',
        })
      }
    }

    const handleScanSuccess = () => {
      setScanStatus('success')
      setFaviconStatus('success')
      setTimeout(() => {
        setScanStatus('idle')
        setFaviconStatus('idle')
      }, 5000)
    }

    window.addEventListener('netra:scan-start', handleScanStart)
    window.addEventListener('netra:scan-complete', handleScanComplete)
    window.addEventListener('netra:scan-success', handleScanSuccess)

    return () => {
      window.removeEventListener('netra:scan-start', handleScanStart)
      window.removeEventListener('netra:scan-complete', handleScanComplete)
      window.removeEventListener('netra:scan-success', handleScanSuccess)
    }
  }, [setFaviconStatus])

  // Listen for show shortcuts event
  useEffect(() => {
    const handleShowShortcuts = () => setShowShortcutsModal(true)
    window.addEventListener('netra:show-shortcuts', handleShowShortcuts)

    return () => {
      window.removeEventListener('netra:show-shortcuts', handleShowShortcuts)
    }
  }, [])

  return (
    <>
      <div className="flex h-screen bg-background">
        {/* Desktop: sidebar always visible */}
        <div className="hidden md:block">
          <Sidebar />
        </div>

        {/* Mobile: the menu button opens the sidebar as a drawer */}
        {mobileNavOpen && (
          <div className="fixed inset-0 z-50 flex md:hidden" role="dialog" aria-label="Navigation">
            <div className="h-full">
              <Sidebar />
            </div>
            <button
              type="button"
              className="flex-1 bg-black/60"
              aria-label="Close navigation"
              onClick={() => setMobileNavOpen(false)}
            />
          </div>
        )}

        <div className="flex flex-1 flex-col overflow-hidden">
          <Header onMenuClick={() => setMobileNavOpen((open) => !open)} />
          <main className="flex-1 overflow-auto p-4 md:p-6">
            {children}
          </main>
          <footer className="border-t border-border px-4 py-2 text-xs text-muted-foreground md:px-6">
            NETRA v1.0.0 · The Third Eye of Security · AGPL-3.0
          </footer>
        </div>
      </div>

      {/* Global Keyboard Shortcuts Modal */}
      <KeyboardShortcutsModal
        isOpen={showShortcutsModal}
        onClose={() => setShowShortcutsModal(false)}
      />
    </>
  )
}
