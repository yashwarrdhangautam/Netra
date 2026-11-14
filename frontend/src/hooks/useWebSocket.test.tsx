import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useWebSocket } from './useWebSocket'

// A WebSocket stand-in that records every instance and lets the test drive open and close.
class FakeSocket {
  static instances: FakeSocket[] = []
  static OPEN = 1
  readyState = 0
  onopen: (() => void) | null = null
  onclose: (() => void) | null = null
  onerror: ((e: unknown) => void) | null = null
  onmessage: ((e: { data: string }) => void) | null = null
  constructor(public url: string) {
    FakeSocket.instances.push(this)
  }
  close() {
    this.readyState = 3
    this.onclose?.()
  }
  send() {}
}

describe('useWebSocket', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    FakeSocket.instances = []
    vi.stubGlobal('WebSocket', FakeSocket)
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('delivers parsed JSON messages', () => {
    const onMessage = vi.fn()
    renderHook(() => useWebSocket({ url: 'ws://t/a', onMessage }))
    act(() => FakeSocket.instances[0].onmessage?.({ data: '{"status":"running"}' }))
    expect(onMessage).toHaveBeenCalledWith({ status: 'running' })
  })

  it('reconnects after an unexpected close', () => {
    renderHook(() => useWebSocket({ url: 'ws://t/a', onMessage: () => {}, reconnectInterval: 1000 }))
    act(() => FakeSocket.instances[0].onclose?.())
    act(() => vi.advanceTimersByTime(1000))
    expect(FakeSocket.instances).toHaveLength(2)
  })

  it('does not reconnect once the caller disables it, so a finished scan does not loop', () => {
    const { rerender } = renderHook(
      ({ enabled }: { enabled: boolean }) =>
        useWebSocket({ url: 'ws://t/a', onMessage: () => {}, enabled, reconnectInterval: 1000 }),
      { initialProps: { enabled: true } },
    )
    // The server closes the socket after the scan ends, and the page turns the socket off.
    act(() => rerender({ enabled: false }))
    act(() => FakeSocket.instances[0].onclose?.())
    act(() => vi.advanceTimersByTime(5000))
    expect(FakeSocket.instances).toHaveLength(1)
  })

  it('does not reconnect after unmount', () => {
    const { unmount } = renderHook(() =>
      useWebSocket({ url: 'ws://t/a', onMessage: () => {}, reconnectInterval: 1000 }),
    )
    unmount()
    act(() => FakeSocket.instances[0].onclose?.())
    act(() => vi.advanceTimersByTime(5000))
    expect(FakeSocket.instances).toHaveLength(1)
  })
})
