/** Only http(s) URLs become links: a target-supplied javascript: or data: URL must never be clickable. */
export function safeHref(url: string | undefined | null): string | null {
  if (!url) return null
  try {
    const parsed = new URL(url)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.href : null
  } catch {
    return null
  }
}
