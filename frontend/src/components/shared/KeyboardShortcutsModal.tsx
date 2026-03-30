import { X, Keyboard, Command } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts'

interface KeyboardShortcutsModalProps {
  isOpen: boolean
  onClose: () => void
}

export function KeyboardShortcutsModal({ isOpen, onClose }: KeyboardShortcutsModalProps) {
  const { shortcuts } = useKeyboardShortcuts()
  const [mounted, setMounted] = useState(false)

  // Group shortcuts by category
  const groupedShortcuts = shortcuts.reduce((acc, shortcut) => {
    if (!acc[shortcut.category]) {
      acc[shortcut.category] = []
    }
    acc[shortcut.category].push(shortcut)
    return acc
  }, {} as Record<string, typeof shortcuts>)

  useEffect(() => {
    setMounted(true)
    return () => setMounted(false)
  }, [])

  // Close on Escape
  useEffect(() => {
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && isOpen) {
        onClose()
      }
    }

    if (isOpen) {
      window.addEventListener('keydown', handleEscape)
      return () => window.removeEventListener('keydown', handleEscape)
    }
  }, [isOpen, onClose])

  if (!isOpen || !mounted) return null

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 backdrop-blur-sm p-4 pt-20">
      <div 
        className="w-full max-w-2xl rounded-lg bg-surface border border-border shadow-2xl animate-in fade-in zoom-in duration-200"
        role="dialog"
        aria-modal="true"
        aria-labelledby="shortcuts-modal-title"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border px-6 py-4">
          <div className="flex items-center space-x-3">
            <Keyboard className="h-5 w-5 text-accent" />
            <h2 id="shortcuts-modal-title" className="text-lg font-semibold text-foreground">
              Keyboard Shortcuts
            </h2>
          </div>
          <button
            onClick={onClose}
            className="rounded-md p-1 text-muted-foreground hover:bg-surface-2 hover:text-foreground transition-colors"
            aria-label="Close shortcuts modal"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="max-h-[60vh] overflow-y-auto px-6 py-4">
          {Object.entries(groupedShortcuts).map(([category, categoryShortcuts]) => (
            <div key={category} className="mb-6 last:mb-0">
              <h3 className="mb-3 text-sm font-medium text-muted-foreground uppercase tracking-wider">
                {category}
              </h3>
              <div className="space-y-2">
                {categoryShortcuts.map((shortcut) => (
                  <div
                    key={shortcut.key}
                    className="flex items-center justify-between py-2 border-b border-surface-2 last:border-0"
                  >
                    <span className="text-sm text-foreground">{shortcut.description}</span>
                    <div className="flex items-center space-x-2">
                      {shortcut.key === ' ' ? (
                        <kbd className="inline-flex min-w-[3rem] items-center justify-center rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs font-medium text-foreground shadow-sm">
                          Space
                        </kbd>
                      ) : shortcut.key === 'Escape' ? (
                        <kbd className="inline-flex min-w-[4rem] items-center justify-center rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs font-medium text-foreground shadow-sm">
                          Esc
                        </kbd>
                      ) : (
                        <kbd className="inline-flex min-w-[2rem] items-center justify-center rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs font-medium text-foreground shadow-sm uppercase">
                          {shortcut.key}
                        </kbd>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="border-t border-border px-6 py-4 bg-surface-2 rounded-b-lg">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <div className="flex items-center space-x-2">
              <Command className="h-3.5 w-3.5" />
              <span>Press any shortcut key to trigger action</span>
            </div>
            <span>Press <kbd className="inline-flex items-center justify-center rounded border border-border bg-surface px-1.5 py-0.5 text-xs font-medium">Esc</kbd> to close</span>
          </div>
        </div>
      </div>
    </div>
  )
}
