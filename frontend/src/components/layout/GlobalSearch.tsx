import { useEffect, useRef, useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { searchApi } from '@/api/platform'

/** Header search across findings, scans and targets. Debounced; keyboard friendly. */
export function GlobalSearch() {
  const navigate = useNavigate()
  const [text, setText] = useState('')
  const [debounced, setDebounced] = useState('')
  const [open, setOpen] = useState(false)
  const box = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(text.trim()), 300)
    return () => window.clearTimeout(timer)
  }, [text])

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [])

  const { data, isFetching, error } = useQuery({
    queryKey: ['global-search', debounced],
    queryFn: () => searchApi.query(debounced),
    enabled: debounced.length >= 2,
    staleTime: 10_000,
  })

  const total = data ? data.findings.length + data.scans.length + data.targets.length : 0

  const go = (to: string, params?: Record<string, string>) => {
    setOpen(false)
    setText('')
    if (params) {
      navigate({ to: to as never, params: params as never })
    } else {
      navigate({ to: to as never })
    }
  }

  return (
    <div ref={box} className="relative w-full max-w-md">
      <label htmlFor="global-search" className="sr-only">
        Search findings, scans and targets
      </label>
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" aria-hidden="true" />
        <input
          id="global-search"
          type="search"
          value={text}
          placeholder="Search findings, scans, targets…"
          onChange={(e) => {
            setText(e.target.value)
            setOpen(true)
          }}
          onFocus={() => setOpen(true)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') setOpen(false)
          }}
          className="w-full rounded-md border border-border bg-surface-2 py-2 pl-9 pr-3 text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent"
        />
      </div>

      {open && debounced.length >= 2 && (
        <div className="absolute z-40 mt-1 max-h-96 w-full overflow-y-auto rounded-md border border-border bg-surface shadow-lg">
          {isFetching && <p className="p-3 text-sm text-muted-foreground">Searching…</p>}
          {error && <p className="p-3 text-sm text-red-400">Search failed. Try again.</p>}
          {!isFetching && !error && total === 0 && (
            <p className="p-3 text-sm text-muted-foreground">No matches for “{debounced}”.</p>
          )}
          {data?.findings.map((f) => (
            <button key={`f-${f.id}`} type="button" onClick={() => go('/findings/$findingId', { findingId: f.id })}
              className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm hover:bg-surface-2">
              <span className="truncate">{f.title}</span>
              <span className="text-xs text-muted-foreground">finding · {f.severity}</span>
            </button>
          ))}
          {data?.scans.map((s) => (
            <button key={`s-${s.id}`} type="button" onClick={() => go('/scans/$scanId', { scanId: s.id })}
              className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm hover:bg-surface-2">
              <span className="truncate">{s.name}</span>
              <span className="text-xs text-muted-foreground">scan · {s.status}</span>
            </button>
          ))}
          {data?.targets.map((t) => (
            <button key={`t-${t.id}`} type="button" onClick={() => go('/targets')}
              className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm hover:bg-surface-2">
              <span className="truncate">{t.name}</span>
              <span className="text-xs text-muted-foreground">target · {t.value}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
