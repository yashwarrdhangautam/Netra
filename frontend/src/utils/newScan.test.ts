import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { NEW_SCAN_EVENT, consumePendingNewScan, requestNewScan } from './newScan'

describe('requestNewScan', () => {
  beforeEach(() => sessionStorage.clear())
  afterEach(() => window.history.pushState({}, '', '/'))

  it('navigates to /scans and leaves a one-shot flag when called from another page', () => {
    window.history.pushState({}, '', '/')
    const navigate = vi.fn()
    const heard = vi.fn()
    window.addEventListener(NEW_SCAN_EVENT, heard)

    requestNewScan(navigate)
    window.removeEventListener(NEW_SCAN_EVENT, heard)

    expect(navigate).toHaveBeenCalledWith({ to: '/scans' })
    expect(heard).not.toHaveBeenCalled()
    expect(consumePendingNewScan()).toBe(true)
    expect(consumePendingNewScan()).toBe(false)
  })

  it('dispatches the event without navigating when already on /scans', () => {
    window.history.pushState({}, '', '/scans')
    const navigate = vi.fn()
    const heard = vi.fn()
    window.addEventListener(NEW_SCAN_EVENT, heard)

    requestNewScan(navigate)
    window.removeEventListener(NEW_SCAN_EVENT, heard)

    expect(heard).toHaveBeenCalledTimes(1)
    expect(navigate).not.toHaveBeenCalled()
    expect(consumePendingNewScan()).toBe(false)
  })
})
