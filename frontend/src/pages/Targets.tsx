import { useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Globe, Server, Link, Pencil, Upload } from 'lucide-react'
import { targetsApi, type CreateTargetPayload } from '@/api/targets'
import { targetsExtraApi } from '@/api/platform'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { DataTable } from '@/components/shared/DataTable'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingSkeleton } from '@/components/shared/LoadingSkeleton'
import { NotificationBanner, type BannerMessage } from '@/components/shared/NotificationBanner'
import { useAuthStore } from '@/stores/authStore'
import { cn, formatDate } from '@/utils/formatters'
import type { ColumnDef } from '@tanstack/react-table'
import type { Target } from '@/types'

type TargetType = CreateTargetPayload['target_type']

const TARGET_TYPE_ICONS: Record<string, React.ReactNode> = {
  domain: <Globe className="w-4 h-4" />,
  ip: <Server className="w-4 h-4" />,
  url: <Link className="w-4 h-4" />,
  ip_range: <Server className="w-4 h-4" />,
  domain_list: <Globe className="w-4 h-4" />,
}

const INPUT = cn(
  'w-full px-3 py-2 rounded-md text-sm transition-colors',
  'bg-surface-2 text-foreground border border-border',
  'placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent'
)

function errorText(err: unknown, fallback: string): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

const PLACEHOLDER: Record<TargetType, string> = {
  domain: 'example.com',
  ip: '192.168.1.1',
  url: 'https://example.com/api',
  ip_range: '192.168.1.0/24',
  domain_list: 'domains.txt',
}

interface TargetRow extends Target {
  group_name?: string | null
  client_id?: string | null
}

export function Targets() {
  const queryClient = useQueryClient()
  const canEdit = useAuthStore((s) => s.canEdit)()
  const fileInput = useRef<HTMLInputElement>(null)

  const [groupFilter, setGroupFilter] = useState('')
  const [message, setMessage] = useState<BannerMessage | null>(null)
  const [adding, setAdding] = useState(false)
  const [form, setForm] = useState({ name: '', targetType: 'domain' as TargetType, value: '', group: '' })
  const [editing, setEditing] = useState<TargetRow | null>(null)
  const [editForm, setEditForm] = useState({ name: '', value: '', group: '', client: '' })
  const clientUsers = useQuery({
    queryKey: ['target-clients'],
    queryFn: targetsExtraApi.clients,
    enabled: editing !== null,
  })
  const [confirmDelete, setConfirmDelete] = useState<TargetRow | null>(null)

  const { data, isLoading, error } = useQuery({
    queryKey: ['targets', groupFilter],
    queryFn: () =>
      targetsApi.list(groupFilter ? ({ group: groupFilter } as Record<string, string>) : undefined),
  })

  const { data: groups = [] } = useQuery({
    queryKey: ['target-groups'],
    queryFn: targetsExtraApi.groups,
  })

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['targets'] })
    await queryClient.invalidateQueries({ queryKey: ['target-groups'] })
  }

  const createMutation = useMutation({
    mutationFn: (payload: CreateTargetPayload & { group_name?: string }) =>
      targetsApi.create(payload),
    onSuccess: async () => {
      setAdding(false)
      setForm({ name: '', targetType: 'domain', value: '', group: '' })
      setMessage({ type: 'success', text: 'Target added.' })
      await refresh()
    },
    onError: (err) => setMessage({ type: 'error', text: errorText(err, 'Could not add the target.') }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) =>
      targetsExtraApi.update(id, body),
    onSuccess: async () => {
      setEditing(null)
      setMessage({ type: 'success', text: 'Target updated.' })
      await refresh()
    },
    onError: (err) => setMessage({ type: 'error', text: errorText(err, 'Could not update the target.') }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => targetsApi.delete(id),
    onSuccess: async () => {
      setConfirmDelete(null)
      setMessage({ type: 'success', text: 'Target deleted.' })
      await refresh()
    },
    onError: (err) => {
      setConfirmDelete(null)
      setMessage({ type: 'error', text: errorText(err, 'Could not delete the target.') })
    },
  })

  const importMutation = useMutation({
    mutationFn: (file: File) => targetsApi.importTargets(file),
    onSuccess: async (result) => {
      const failed = result.failed ? ` ${result.failed} row(s) were rejected.` : ''
      setMessage({
        type: result.imported > 0 ? 'success' : 'error',
        text: `Imported ${result.imported} target(s).${failed}`,
      })
      await refresh()
    },
    onError: (err) => setMessage({ type: 'error', text: errorText(err, 'The CSV could not be imported.') }),
    onSettled: () => {
      if (fileInput.current) fileInput.current.value = ''
    },
  })

  const rows: TargetRow[] = ((data?.items ?? []) as TargetRow[]).map((t) => t)

  const columns: ColumnDef<TargetRow>[] = [
    {
      accessorKey: 'name',
      header: 'Name',
      cell: ({ row }) => <div className="font-medium">{row.original.name}</div>,
    },
    {
      accessorKey: 'target_type',
      header: 'Type',
      cell: ({ row }) => {
        const type = String(row.original.target_type)
        return (
          <div className="flex items-center gap-2">
            {TARGET_TYPE_ICONS[type] || <Globe className="w-4 h-4" />}
            <Badge variant="secondary">{type}</Badge>
          </div>
        )
      },
    },
    {
      accessorKey: 'value',
      header: 'Value',
      cell: ({ row }) => <code className="text-xs">{row.original.value}</code>,
    },
    {
      id: 'group',
      header: 'Group',
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">{row.original.group_name || '—'}</span>
      ),
    },
    {
      id: 'created',
      header: 'Created',
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">{formatDate(row.original.created_at)}</span>
      ),
    },
    ...(canEdit
      ? [
          {
            id: 'actions',
            header: '',
            cell: ({ row }: { row: { original: TargetRow } }) => (
              <div className="flex items-center gap-1">
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label={`Edit ${row.original.name}`}
                  onClick={() => {
                    setEditing(row.original)
                    setEditForm({
                      name: row.original.name,
                      value: row.original.value,
                      group: row.original.group_name || '',
                      client: row.original.client_id || '',
                    })
                  }}
                >
                  <Pencil className="w-4 h-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label={`Delete ${row.original.name}`}
                  onClick={() => setConfirmDelete(row.original)}
                  className="text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-950"
                >
                  <Trash2 className="w-4 h-4" />
                </Button>
              </div>
            ),
          } as ColumnDef<TargetRow>,
        ]
      : []),
  ]

  if (isLoading) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">Targets</h1>
        <LoadingSkeleton variant="table" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">Targets</h1>
        <NotificationBanner
          message={{ type: 'error', text: errorText(error, 'Could not load targets.') }}
          onDismiss={() => undefined}
          autoHideMs={0}
        />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Targets</h1>
          <p className="text-sm text-muted-foreground">
            Hosts, domains and ranges you scan. Every target is checked against the SSRF rules when saved.
          </p>
        </div>
        {canEdit && (
          <div className="flex gap-2">
            <input
              ref={fileInput}
              type="file"
              accept=".csv,text/csv"
              className="hidden"
              aria-label="CSV file"
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (file) importMutation.mutate(file)
              }}
            />
            <Button
              variant="outline"
              onClick={() => fileInput.current?.click()}
              disabled={importMutation.isPending}
            >
              <Upload className="w-4 h-4 mr-2" />
              {importMutation.isPending ? 'Importing…' : 'Import CSV'}
            </Button>
            <Button onClick={() => setAdding((v) => !v)} disabled={adding && createMutation.isPending}>
              <Plus className="w-4 h-4 mr-2" />
              {adding ? 'Close' : 'Add target'}
            </Button>
          </div>
        )}
      </div>

      <NotificationBanner message={message} onDismiss={() => setMessage(null)} />

      {adding && canEdit && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">New target</CardTitle>
          </CardHeader>
          <CardContent>
            <form
              className="grid grid-cols-1 gap-4 md:grid-cols-2"
              onSubmit={(e) => {
                e.preventDefault()
                createMutation.mutate({
                  name: form.name,
                  target_type: form.targetType,
                  value: form.value,
                  group_name: form.group || undefined,
                } as CreateTargetPayload & { group_name?: string })
              }}
            >
              <label className="space-y-1 text-sm">
                <span className="font-medium">Name</span>
                <input className={INPUT} required value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </label>
              <label className="space-y-1 text-sm">
                <span className="font-medium">Type</span>
                <select className={INPUT} value={form.targetType}
                  onChange={(e) => setForm({ ...form, targetType: e.target.value as TargetType })}>
                  <option value="domain">Domain</option>
                  <option value="ip">IP address</option>
                  <option value="url">URL</option>
                  <option value="ip_range">IP range</option>
                  <option value="domain_list">Domain list</option>
                </select>
              </label>
              <label className="space-y-1 text-sm md:col-span-2">
                <span className="font-medium">Value</span>
                <input className={INPUT} required placeholder={PLACEHOLDER[form.targetType]}
                  value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} />
              </label>
              <label className="space-y-1 text-sm">
                <span className="font-medium">Group (optional)</span>
                <input className={INPUT} list="target-groups" value={form.group}
                  onChange={(e) => setForm({ ...form, group: e.target.value })} />
              </label>
              <div className="flex items-end justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setAdding(false)}>Cancel</Button>
                <Button type="submit" disabled={createMutation.isPending}>
                  {createMutation.isPending ? 'Adding…' : 'Add target'}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      <div className="flex items-center gap-3 text-sm">
        <label htmlFor="group-filter" className="text-muted-foreground">Group</label>
        <select id="group-filter" className={cn(INPUT, 'w-auto')} value={groupFilter}
          onChange={(e) => setGroupFilter(e.target.value)}>
          <option value="">All groups</option>
          {groups.map((g) => <option key={g} value={g}>{g}</option>)}
        </select>
        <datalist id="target-groups">
          {groups.map((g) => <option key={g} value={g} />)}
        </datalist>
      </div>

      {rows.length === 0 ? (
        <EmptyState
          icon={Globe}
          title={groupFilter ? 'No targets in this group' : 'No targets yet'}
          description={
            canEdit
              ? 'Add a target, or import a CSV with name, target_type, value and group columns.'
              : 'An analyst or admin needs to add targets.'
          }
        />
      ) : (
        <Card>
          <CardContent className="pt-6">
            <DataTable<TargetRow, unknown> columns={columns} data={rows} />
          </CardContent>
        </Card>
      )}

      {editing && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <Card className="w-full max-w-md">
            <CardHeader>
              <CardTitle className="text-lg">Edit target</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <label className="block space-y-1 text-sm">
                <span className="font-medium">Name</span>
                <input className={INPUT} value={editForm.name}
                  onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} />
              </label>
              <label className="block space-y-1 text-sm">
                <span className="font-medium">Value</span>
                <input className={INPUT} value={editForm.value}
                  onChange={(e) => setEditForm({ ...editForm, value: e.target.value })} />
              </label>
              <label className="block space-y-1 text-sm">
                <span className="font-medium">Group</span>
                <input className={INPUT} list="target-groups" value={editForm.group}
                  onChange={(e) => setEditForm({ ...editForm, group: e.target.value })} />
              </label>
              <label className="block space-y-1 text-sm">
                <span className="font-medium">Assigned client</span>
                <select className={INPUT} value={editForm.client}
                  onChange={(e) => setEditForm({ ...editForm, client: e.target.value })}>
                  <option value="">Not assigned</option>
                  {(clientUsers.data ?? []).map((c) => (
                    <option key={c.id} value={c.id}>{c.full_name ? `${c.full_name} (${c.email})` : c.email}</option>
                  ))}
                </select>
                <span className="text-xs text-muted-foreground">
                  Clients see only the targets assigned to them, their scans, findings and reports.
                </span>
              </label>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => setEditing(null)}>Cancel</Button>
                <Button
                  disabled={updateMutation.isPending}
                  onClick={() =>
                    updateMutation.mutate({
                      id: editing.id,
                      body: {
                        name: editForm.name,
                        value: editForm.value,
                        group_name: editForm.group || null,
                        client_id: editForm.client || null,
                      },
                    })
                  }
                >
                  {updateMutation.isPending ? 'Saving…' : 'Save'}
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <Card className="w-full max-w-sm">
            <CardHeader>
              <CardTitle className="text-lg">Delete target?</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Delete <span className="font-medium text-foreground">{confirmDelete.name}</span>? This cannot
                be undone. Targets that still have scans cannot be deleted.
              </p>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => setConfirmDelete(null)}>Cancel</Button>
                <Button variant="destructive" disabled={deleteMutation.isPending}
                  onClick={() => deleteMutation.mutate(confirmDelete.id)}>
                  {deleteMutation.isPending ? 'Deleting…' : 'Delete'}
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}
