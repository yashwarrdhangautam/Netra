import { useEffect, useCallback } from 'react'
import { useNavigate } from '@tanstack/react-router'

interface ShortcutConfig {
  key: string
  handler: () => void
  description: string
  category: string
  disabled?: boolean
}

interface UseKeyboardShortcutsOptions {
  onNewScan?: () => void
  onSearch?: () => void
  onShowHelp?: () => void
}

/**
 * Keyboard shortcuts for NETRA dashboard
 * 
 * Shortcuts:
 * - N: New Scan
 * - /: Focus search
 * - ?: Show shortcuts help
 * - G: Go to Dashboard
 * - S: Go to Scans
 * - F: Go to Findings
 * - R: Generate Report
 * - Esc: Close modal / Cancel search
 */
export function useKeyboardShortcuts({
  onNewScan,
  onSearch,
  onShowHelp,
}: UseKeyboardShortcutsOptions = {}) {
  const navigate = useNavigate()

  const defaultHandlers = {
    handleNewScan: useCallback(() => {
      if (onNewScan) {
        onNewScan()
      } else {
        // Default: navigate to scans page with new scan modal trigger
        console.log('New Scan shortcut triggered')
        // Dispatch custom event for modal to listen to
        window.dispatchEvent(new CustomEvent('netra:new-scan'))
      }
    }, [onNewScan]),

    handleSearch: useCallback(() => {
      if (onSearch) {
        onSearch()
      } else {
        // Default: focus search input if exists
        const searchInput = document.querySelector('input[type="text"][placeholder*="Search"]')
        if (searchInput) {
          (searchInput as HTMLInputElement).focus()
        } else {
          console.log('Search shortcut triggered - no search input found')
        }
      }
    }, [onSearch]),

    handleShowHelp: useCallback(() => {
      if (onShowHelp) {
        onShowHelp()
      } else {
        // Default: dispatch event to show help modal
        window.dispatchEvent(new CustomEvent('netra:show-shortcuts'))
      }
    }, [onShowHelp]),

    handleGoToDashboard: useCallback(() => {
      navigate({ to: '/' })
    }, [navigate]),

    handleGoToScans: useCallback(() => {
      navigate({ to: '/scans' })
    }, [navigate]),

    handleGoToFindings: useCallback(() => {
      navigate({ to: '/findings' })
    }, [navigate]),

    handleGoToReports: useCallback(() => {
      navigate({ to: '/reports' })
    }, [navigate]),

    handleGenerateReport: useCallback(() => {
      console.log('Generate Report shortcut triggered')
      window.dispatchEvent(new CustomEvent('netra:generate-report'))
    }, []),
  }

  const shortcuts: ShortcutConfig[] = [
    {
      key: 'N',
      handler: defaultHandlers.handleNewScan,
      description: 'New Scan',
      category: 'Actions',
    },
    {
      key: '/',
      handler: defaultHandlers.handleSearch,
      description: 'Focus Search',
      category: 'Navigation',
    },
    {
      key: '?',
      handler: defaultHandlers.handleShowHelp,
      description: 'Show Shortcuts Help',
      category: 'Help',
    },
    {
      key: 'G',
      handler: defaultHandlers.handleGoToDashboard,
      description: 'Go to Dashboard',
      category: 'Navigation',
    },
    {
      key: 'S',
      handler: defaultHandlers.handleGoToScans,
      description: 'Go to Scans',
      category: 'Navigation',
    },
    {
      key: 'F',
      handler: defaultHandlers.handleGoToFindings,
      description: 'Go to Findings',
      category: 'Navigation',
    },
    {
      key: 'R',
      handler: defaultHandlers.handleGenerateReport,
      description: 'Generate Report',
      category: 'Actions',
    },
    {
      key: 'Escape',
      handler: () => {
        // Close modal or blur search
        const activeElement = document.activeElement as HTMLElement
        if (activeElement && activeElement.tagName === 'INPUT') {
          activeElement.blur()
        }
        window.dispatchEvent(new CustomEvent('netra:close-modal'))
      },
      description: 'Close Modal / Cancel Search',
      category: 'General',
    },
  ]

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      // Ignore if typing in input/textarea
      const target = event.target as HTMLElement
      if (
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.isContentEditable
      ) {
        // Allow Escape to work even in inputs
        if (event.key === 'Escape') {
          const shortcut = shortcuts.find(s => s.key === 'Escape')
          if (shortcut) {
            shortcut.handler()
          }
        }
        return
      }

      // Ignore if modifier keys are pressed (to avoid conflicts with browser shortcuts)
      if (event.ctrlKey || event.altKey || event.metaKey) {
        return
      }

      // Find matching shortcut
      const shortcut = shortcuts.find(s => s.key === event.key)
      
      if (shortcut && !shortcut.disabled) {
        event.preventDefault()
        shortcut.handler()
      }
    }

    window.addEventListener('keydown', handleKeyDown)

    return () => {
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [shortcuts])

  return {
    shortcuts: shortcuts.filter(s => !s.disabled),
  }
}
