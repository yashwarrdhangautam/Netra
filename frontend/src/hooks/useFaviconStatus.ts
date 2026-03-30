import { useEffect, useCallback } from 'react'

type FaviconStatus = 'idle' | 'scanning' | 'complete' | 'success'

interface UseFaviconStatusOptions {
  status?: FaviconStatus
  enabled?: boolean
}

/**
 * Dynamic favicon with status indicator
 * - Default: NETRA third eye (blue/purple)
 * - Scanning: Yellow dot overlay
 * - Complete: Red dot overlay
 * - Success: Green dot overlay
 */
export function useFaviconStatus({
  status = 'idle',
  enabled = true,
}: UseFaviconStatusOptions = {}) {
  const setFaviconStatus = useCallback((newStatus: FaviconStatus) => {
    if (!enabled) return

    const link = document.querySelector("link[rel*='icon']") as HTMLLinkElement
    if (!link) return

    // Create status-specific favicon
    const statusColors: Record<FaviconStatus, string> = {
      idle: '',
      scanning: '#fbbf24', // Yellow
      complete: '#ef4444', // Red
      success: '#22c55e', // Green
    }

    const statusColor = statusColors[newStatus]

    if (newStatus === 'idle' || !statusColor) {
      // Reset to default favicon
      link.href = '/favicon.svg'
      return
    }

    // Create data URI with status indicator
    const baseFavicon = `
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
        <defs>
          <linearGradient id="eyeGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:#3b82f6;stop-opacity:1" />
            <stop offset="100%" style="stop-color:#8b5cf6;stop-opacity:1" />
          </linearGradient>
        </defs>
        <ellipse cx="16" cy="16" rx="14" ry="10" fill="url(#eyeGradient)" opacity="0.9"/>
        <ellipse cx="16" cy="16" rx="10" ry="7" fill="#1e293b"/>
        <circle cx="16" cy="16" r="5" fill="#3b82f6"/>
        <circle cx="18" cy="14" r="2" fill="#ffffff" opacity="0.8"/>
        <circle cx="16" cy="16" r="2" fill="#ffffff" opacity="0.6"/>
        <!-- Status indicator -->
        <circle cx="24" cy="8" r="6" fill="${statusColor}" stroke="#ffffff" stroke-width="1"/>
      </svg>
    `

    const svgBlob = new Blob([baseFavicon], { type: 'image/svg+xml' })
    const url = URL.createObjectURL(svgBlob)
    link.href = url

    // Cleanup old URL after a delay
    return () => URL.revokeObjectURL(url)
  }, [enabled])

  // Update favicon when status changes
  useEffect(() => {
    const cleanup = setFaviconStatus(status)
    return () => {
      if (cleanup) cleanup()
    }
  }, [status, setFaviconStatus])

  // Helper to request notification permission
  const requestNotificationPermission = useCallback(async () => {
    if (!('Notification' in window)) {
      console.warn('Notifications not supported')
      return false
    }

    if (Notification.permission === 'granted') {
      return true
    }

    if (Notification.permission !== 'denied') {
      const permission = await Notification.requestPermission()
      return permission === 'granted'
    }

    return false
  }, [])

  // Show browser notification
  const showNotification = useCallback((title: string, body: string) => {
    if (Notification.permission === 'granted') {
      new Notification(title, {
        body,
        icon: '/favicon.svg',
        badge: '/favicon.svg',
      })
    }
  }, [])

  return {
    setFaviconStatus,
    requestNotificationPermission,
    showNotification,
  }
}
