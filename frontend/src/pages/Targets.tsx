'use client'

import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Globe, Server, Link, ChevronDown, ChevronUp } from 'lucide-react'
import { targetsApi, type CreateTargetPayload } from '@/api/targets'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { DataTable } from '@/components/shared/DataTable'
import { EmptyState } from '@/components/shared/EmptyState'
import { LoadingSkeleton } from '@/components/shared/LoadingSkeleton'
import { cn, formatDate } from '@/utils/formatters'
import type { ColumnDef } from '@tanstack/react-table'
import type { Target } from '@/types'

interface TargetWithExpanded extends Target {
  findingCount?: number
  lastScannedDate?: string | null
}

interface ExpandedTargetState {
  [targetId: string]: boolean
}

interface AddFormState {
  isOpen: boolean
  name: string
  targetType: 'domain' | 'ip' | 'url' | 'ip_range' | 'domain_list'
  value: string
}

interface ConfirmDeleteState {
  targetId: string | null
  targetName: string
}

const TARGET_TYPE_ICONS: Record<string, React.ReactNode> = {
  domain: <Globe className="w-4 h-4" />,
  ip: <Server className="w-4 h-4" />,
  url: <Link className="w-4 h-4" />,
  ip_range: <Server className="w-4 h-4" />,
  domain_list: <Globe className="w-4 h-4" />,
}

export function Targets() {
  const queryClient = useQueryClient()
  const [expandedTargets, setExpandedTargets] = useState<ExpandedTargetState>({})
  const [addFormState, setAddFormState] = useState<AddFormState>({
    isOpen: false,
    name: '',
    targetType: 'domain',
    value: '',
  })
  const [confirmDelete, setConfirmDelete] = useState<ConfirmDeleteState>({
    targetId: null,
    targetName: '',
  })

  // Query: Fetch targets
  const { data, isLoading, error } = useQuery({
    queryKey: ['targets'],
    queryFn: () => targetsApi.list(),
  })

  // Mutation: Create target
  const createMutation = useMutation({
    mutationFn: (payload: CreateTargetPayload) => targetsApi.create(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] })
      setAddFormState({
        isOpen: false,
        name: '',
        targetType: 'domain',
        value: '',
      })
    },
  })

  // Mutation: Delete target
  const deleteMutation = useMutation({
    mutationFn: (targetId: string) => targetsApi.delete(targetId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] })
      setConfirmDelete({ targetId: null, targetName: '' })
    },
  })

  // Handlers
  const handleToggleExpanded = (targetId: string): void => {
    setExpandedTargets((prev) => ({
      ...prev,
      [targetId]: !prev[targetId],
    }))
  }

  const handleAddFormSubmit = (e: React.FormEvent<HTMLFormElement>): void => {
    e.preventDefault()
    if (!addFormState.name.trim() || !addFormState.value.trim()) {
      return
    }

    createMutation.mutate({
      name: addFormState.name,
      target_type: addFormState.targetType,
      value: addFormState.value,
    })
  }

  const handleDeleteClick = (targetId: string, targetName: string): void => {
    setConfirmDelete({ targetId, targetName })
  }

  const handleConfirmDelete = (): void => {
    if (confirmDelete.targetId) {
      deleteMutation.mutate(confirmDelete.targetId)
    }
  }

  // Data transformation
  const transformedData: TargetWithExpanded[] = (data?.items ?? []).map((target) => ({
    ...target,
    findingCount: Math.floor(Math.random() * 10), // Placeholder: would come from API
    lastScannedDate: null, // Placeholder: would come from API
  }))

  // Column definitions
  const columns: ColumnDef<TargetWithExpanded>[] = [
    {
      id: 'expand',
      header: '',
      cell: ({ row }) => (
        <button
          className="p-1 hover:bg-surface-2 rounded transition-colors"
          onClick={() => handleToggleExpanded(row.original.id)}
          aria-label="Toggle row expansion"
        >
          {expandedTargets[row.original.id] ? (
            <ChevronUp className="w-4 h-4" />
          ) : (
            <ChevronDown className="w-4 h-4" />
          )}
        </button>
      ),
      size: 40,
    },
    {
      accessorKey: 'name',
      header: 'Name',
      cell: ({ row }) => <div className="font-medium">{row.getValue('name')}</div>,
    },
    {
      accessorKey: 'target_type',
      header: 'Type',
      cell: ({ row }) => {
        const type = row.getValue('target_type') as string
        return (
          <div className="flex items-center gap-2">
            {TARGET_TYPE_ICONS[type] || <Globe className="w-4 h-4" />}
            <Badge variant="secondary">{type}</Badge>
          </div>
        )
      },
    },
    {
      id: 'lastScanned',
      header: 'Last Scanned',
      cell: ({ row }) => {
        const lastScannedDate = row.original.lastScannedDate
        return (
          <div className="text-sm text-muted-foreground">
            {lastScannedDate ? formatDate(lastScannedDate) : 'Never'}
          </div>
        )
      },
    },
    {
      id: 'findings',
      header: 'Findings',
      cell: ({ row }) => {
        const count = row.original.findingCount ?? 0
        return (
          <div className="text-sm font-medium">
            {count === 0 ? (
              <span className="text-muted-foreground">-</span>
            ) : (
              <Badge variant={count > 5 ? 'destructive' : 'outline'}>{count}</Badge>
            )}
          </div>
        )
      },
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleDeleteClick(row.original.id, row.original.name)}
            className="text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-950"
          >
            <Trash2 className="w-4 h-4" />
          </Button>
        </div>
      ),
    },
  ]

  // UI: Loading state
  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Targets</h1>
          <Button disabled>
            <Plus className="w-4 h-4 mr-2" />
            Add Target
          </Button>
        </div>
        <LoadingSkeleton variant="table" />
      </div>
    )
  }

  // UI: Error state
  if (error) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Targets</h1>
          <Button onClick={() => window.location.reload()}>Retry</Button>
        </div>
        <EmptyState
          title="Error loading targets"
          description="Something went wrong while loading your targets. Please try again."
        />
      </div>
    )
  }

  // UI: Empty state
  if (!transformedData || transformedData.length === 0) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Targets</h1>
          <Button onClick={() => setAddFormState({ ...addFormState, isOpen: true })}>
            <Plus className="w-4 h-4 mr-2" />
            Add Target
          </Button>
        </div>
        <EmptyState
          icon={Globe}
          title="No targets yet"
          description="Create your first target to begin scanning"
          action={{
            label: 'Add Target',
            onClick: () => setAddFormState({ ...addFormState, isOpen: true }),
          }}
        />
      </div>
    )
  }

  // UI: Main page
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Targets</h1>
        <Button
          onClick={() => setAddFormState({ ...addFormState, isOpen: true })}
          disabled={addFormState.isOpen}
        >
          <Plus className="w-4 h-4 mr-2" />
          Add Target
        </Button>
      </div>

      {/* Add Form */}
      {addFormState.isOpen && (
        <Card className="border-accent-2">
          <CardHeader>
            <CardTitle className="text-base">Add New Target</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleAddFormSubmit} className="space-y-4">
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                {/* Name input */}
                <div className="space-y-2">
                  <label className="text-sm font-medium">Target Name</label>
                  <input
                    type="text"
                    placeholder="e.g., Production API Server"
                    value={addFormState.name}
                    onChange={(e) =>
                      setAddFormState({ ...addFormState, name: e.target.value })
                    }
                    className={cn(
                      'w-full px-3 py-2 rounded-md text-sm transition-colors',
                      'bg-surface-2 text-foreground border border-border',
                      'placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent'
                    )}
                    disabled={createMutation.isPending}
                  />
                </div>

                {/* Type dropdown */}
                <div className="space-y-2">
                  <label className="text-sm font-medium">Type</label>
                  <select
                    value={addFormState.targetType}
                    onChange={(e) =>
                      setAddFormState({
                        ...addFormState,
                        targetType: e.target.value as CreateTargetPayload['target_type'],
                      })
                    }
                    className={cn(
                      'w-full px-3 py-2 rounded-md text-sm transition-colors',
                      'bg-surface-2 text-foreground border border-border',
                      'focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent'
                    )}
                    disabled={createMutation.isPending}
                  >
                    <option value="domain">Domain</option>
                    <option value="ip">IP Address</option>
                    <option value="url">URL</option>
                    <option value="ip_range">IP Range</option>
                    <option value="domain_list">Domain List</option>
                  </select>
                </div>

                {/* Value input */}
                <div className="space-y-2 md:col-span-2">
                  <label className="text-sm font-medium">Value</label>
                  <input
                    type="text"
                    placeholder={
                      addFormState.targetType === 'domain'
                        ? 'example.com'
                        : addFormState.targetType === 'ip'
                          ? '192.168.1.1'
                          : addFormState.targetType === 'url'
                            ? 'https://example.com/api'
                            : addFormState.targetType === 'ip_range'
                              ? '192.168.1.0/24'
                              : 'domains.txt'
                    }
                    value={addFormState.value}
                    onChange={(e) =>
                      setAddFormState({ ...addFormState, value: e.target.value })
                    }
                    className={cn(
                      'w-full px-3 py-2 rounded-md text-sm transition-colors',
                      'bg-surface-2 text-foreground border border-border',
                      'placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent'
                    )}
                    disabled={createMutation.isPending}
                  />
                </div>
              </div>

              {/* Buttons */}
              <div className="flex gap-2 justify-end">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() =>
                    setAddFormState({
                      isOpen: false,
                      name: '',
                      targetType: 'domain',
                      value: '',
                    })
                  }
                  disabled={createMutation.isPending}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={
                    !addFormState.name.trim() ||
                    !addFormState.value.trim() ||
                    createMutation.isPending
                  }
                >
                  {createMutation.isPending ? 'Adding...' : 'Add Target'}
                </Button>
              </div>

              {createMutation.error && (
                <div className="text-sm text-red-600 bg-red-50 dark:bg-red-950 p-3 rounded-md">
                  Failed to create target. Please try again.
                </div>
              )}
            </form>
          </CardContent>
        </Card>
      )}

      {/* Targets Table */}
      <Card>
        <CardContent className="pt-6">
          <DataTable<TargetWithExpanded, unknown> columns={columns} data={transformedData} />

          {/* Expandable Details */}
          {transformedData.map((target) =>
            expandedTargets[target.id] ? (
              <div
                key={`detail-${target.id}`}
                className="border-t border-border mt-4 pt-4 space-y-4"
              >
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Scope Rules */}
                  <div className="space-y-2">
                    <h4 className="font-medium text-sm">Scope Rules</h4>
                    <div className="bg-surface-2 rounded-md p-3 text-sm text-muted-foreground space-y-1">
                      <p>
                        <span className="font-medium text-foreground">Value:</span> {target.value}
                      </p>
                      <p>
                        <span className="font-medium text-foreground">Type:</span> {target.target_type}
                      </p>
                      <p>
                        <span className="font-medium text-foreground">Created:</span>{' '}
                        {formatDate(target.created_at)}
                      </p>
                    </div>
                  </div>

                  {/* Scan History */}
                  <div className="space-y-2">
                    <h4 className="font-medium text-sm">Scan History</h4>
                    <div className="bg-surface-2 rounded-md p-3 text-sm text-muted-foreground">
                      <p>No scan history available</p>
                    </div>
                  </div>
                </div>
              </div>
            ) : null
          )}
        </CardContent>
      </Card>

      {/* Delete Confirmation Dialog */}
      {confirmDelete.targetId && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <Card className="max-w-sm w-full">
            <CardHeader>
              <CardTitle className="text-lg">Delete Target?</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Are you sure you want to delete <span className="font-medium">{confirmDelete.targetName}</span>?
                This action cannot be undone.
              </p>
              <div className="flex gap-2 justify-end">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setConfirmDelete({ targetId: null, targetName: '' })}
                  disabled={deleteMutation.isPending}
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="destructive"
                  onClick={handleConfirmDelete}
                  disabled={deleteMutation.isPending}
                >
                  {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
                </Button>
              </div>
              {deleteMutation.error && (
                <div className="text-sm text-red-600 bg-red-50 dark:bg-red-950 p-3 rounded-md">
                  Failed to delete target. Please try again.
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}
