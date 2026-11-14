import { useState } from 'react'
import { Link } from '@tanstack/react-router'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { bugBountyApi } from '@/api/bugbounty'
import { apiClient } from '@/api/client'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table'
import { NotificationBanner, type BannerMessage } from '@/components/shared/NotificationBanner'
import { useAuthStore } from '@/stores/authStore'

/**
 * Bug-bounty settings. The verifier allowlist is read-only here: it is changed in
 * verifier_allowlist.yaml through a reviewed pull request, and the API reloads it.
 * Integration keys (Shodan, WPScan, Slack) are managed on the Settings page.
 */
export function BBSettings() {
  const queryClient = useQueryClient()
  const isAdmin = useAuthStore((s) => s.isAdmin)()
  const [message, setMessage] = useState<BannerMessage | null>(null)

  const verifiers = useQuery({ queryKey: ['bb-verifiers'], queryFn: bugBountyApi.verifiers })

  const reload = useMutation({
    mutationFn: async () => (await apiClient.post('/api/v1/bb/settings/verifiers/reload')).data,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['bb-verifiers'] })
      setMessage({ type: 'success', text: 'Verifier allowlist reloaded from disk.' })
    },
    onError: () => setMessage({ type: 'error', text: 'The allowlist could not be reloaded. Check the file for errors.' }),
  })

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Bug bounty settings</h1>
        <p className="text-sm text-muted-foreground">
          Which read-only checks the PoC lab may run, and where integration keys are kept.
        </p>
      </div>

      <NotificationBanner message={message} onDismiss={() => setMessage(null)} />

      <Card>
        <CardHeader>
          <CardTitle>Verifier allowlist</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            A verifier not on this list cannot run, for any finding. Edit <code>verifier_allowlist.yaml</code> in
            the repository; the API loads it at startup.
          </p>
          {isAdmin && (
            <Button variant="outline" onClick={() => reload.mutate()} disabled={reload.isPending}>
              {reload.isPending ? 'Reloading…' : 'Reload from disk'}
            </Button>
          )}
          {verifiers.isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : (verifiers.data?.length ?? 0) === 0 ? (
            <p className="text-sm text-muted-foreground">No verifiers are loaded.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Verifier</TableHead>
                  <TableHead>Vuln class</TableHead>
                  <TableHead>Methods</TableHead>
                  <TableHead>Description</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {verifiers.data?.map((v) => (
                  <TableRow key={v.id}>
                    <TableCell className="font-mono text-xs">{v.id}</TableCell>
                    <TableCell>
                      <Badge variant="secondary">{v.vuln_class}</Badge>
                    </TableCell>
                    <TableCell className="text-xs">{v.methods.join(', ')}</TableCell>
                    <TableCell className="max-w-md text-sm text-muted-foreground">{v.description}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Integration keys</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>
            Shodan, WPScan and Slack keys are stored encrypted and managed on the{' '}
            <Link to="/settings" className="text-accent underline">Settings page</Link>.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
