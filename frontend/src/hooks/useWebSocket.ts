import { useEffect, useState, useCallback, useRef } from 'react'

interface UseWebSocketOptions {
  url: string
  onMessage: (data: unknown) => void
  reconnectInterval?: number
  enabled?: boolean
}

export function useWebSocket({
  url,
  onMessage,
  reconnectInterval = 3000,
  enabled = true,
}: UseWebSocketOptions) {
  const [isConnected, setIsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  const connect = useCallback(() => {
    if (!enabled) return

    const ws = new WebSocket(url)

    ws.onopen = () => {
      console.log('WebSocket connected:', url)
      setIsConnected(true)
    }

    ws.onclose = () => {
      console.log('WebSocket disconnected:', url)
      setIsConnected(false)
      // Attempt reconnect
      setTimeout(connect, reconnectInterval)
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
  }, [url, onMessage, reconnectInterval, enabled])

  useEffect(() => {
    if (enabled) {
      connect()
    }

    return () => {
      if (wsRef.current) {
        wsRef.current.close()
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
