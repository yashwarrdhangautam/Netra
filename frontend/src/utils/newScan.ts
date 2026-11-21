/**
 * "New scan" requests from anywhere in the app (header button, keyboard shortcut).
 *
 * The create dialog lives on the Scans page, so the page must be mounted to hear the event.
 * Off that page we leave a one-shot flag, navigate there, and the page opens the dialog on mount.
 */
export const NEW_SCAN_EVENT = 'netra:new-scan'
const PENDING_KEY = 'netra:new-scan-pending'
const SCANS_PATH = '/scans'

export function requestNewScan(navigate: (opts: { to: string }) => unknown): void {
  if (window.location.pathname === SCANS_PATH) {
    window.dispatchEvent(new CustomEvent(NEW_SCAN_EVENT))
    return
  }
  try {
    sessionStorage.setItem(PENDING_KEY, '1')
  } catch {
    // Storage can be unavailable; the user still lands on the Scans page.
  }
  navigate({ to: SCANS_PATH })
}

/** True once if a new-scan request is waiting for the Scans page; clears the flag. */
export function consumePendingNewScan(): boolean {
  try {
    if (sessionStorage.getItem(PENDING_KEY) !== '1') return false
    sessionStorage.removeItem(PENDING_KEY)
    return true
  } catch {
    return false
  }
}
