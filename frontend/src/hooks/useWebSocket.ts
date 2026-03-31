import { useEffect, useState, useCallback, useRef } from 'react'

interface UseWebSocketOptions {
  url: string
  onMessage: (data: unknown) => void
  reconnectInterval?: number
  enabled?: boolean
  maxReconnectInterval?: number
}

export function useWebSocket({
  url,
  onMessage,
  reconnectInterval = 1000, // Start with 1 second
  enabled = true,
  maxReconnectInterval = 30000, // Max 30 seconds
}: UseWebSocketOptions) {
  const [isConnected, setIsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const reconnectAttemptsRef = useRef(0)

  const connect = useCallback(() => {
    if (!enabled) return

    const ws = new WebSocket(url)

    ws.onopen = () => {
      console.log('WebSocket connected:', url)
      setIsConnected(true)
      reconnectAttemptsRef.current = 0 // Reset attempts on successful connection
    }

    ws.onclose = () => {
      console.log('WebSocket disconnected:', url)
      setIsConnected(false)
      
      // Calculate exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s, 30s...
      const backoffMs = Math.min(
        reconnectInterval * Math.pow(2, reconnectAttemptsRef.current),
        maxReconnectInterval
      )
      
      reconnectAttemptsRef.current += 1
      
      console.log(
        `WebSocket reconnecting in ${backoffMs}ms (attempt ${reconnectAttemptsRef.current})`
      )
      
      // Clear any existing timeout
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
      
      // Schedule reconnect with backoff
      reconnectTimeoutRef.current = setTimeout(connect, backoffMs)
    }

    ws.onerror = (error) => {
      console.error('WebSocket error:', error)
    }

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        onMessage(data)
      } catch (e) {
        console.error('WebSocket parse error:', e)
      }
    }

    wsRef.current = ws
  }, [url, onMessage, reconnectInterval, maxReconnectInterval, enabled])

  useEffect(() => {
    if (enabled) {
      connect()
    }

    return () => {
      // Cleanup: close WebSocket and clear any pending timeouts
      if (wsRef.current) {
        wsRef.current.close()
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
    }
  }, [connect, enabled])

  const sendMessage = useCallback((data: unknown) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
    }
  }, [])

  return { isConnected, sendMessage }
}
