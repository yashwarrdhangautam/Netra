import { useState } from 'react'
import { Link } from '@tanstack/react-router'
import { authApi } from '@/api/auth'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Shield } from 'lucide-react'

const INPUT_CLASS =
  'w-full rounded border border-border bg-surface-2 p-3 text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary disabled:cursor-not-allowed disabled:opacity-50'

function errorText(err: unknown): string {
  const response = (err as { response?: { status?: number; data?: { detail?: unknown } } })?.response
  const detail = typeof response?.data?.detail === 'string' ? response.data.detail : ''
  if (detail) return detail
  if (response?.status === 429) return 'Too many requests. Wait a while and try again.'
  return 'Could not reach the NETRA API. Check that it is running.'
}

function tokenFromUrl(): string {
  return new URLSearchParams(window.location.search).get('token') ?? ''
}

export function ResetPassword() {
  const token = tokenFromUrl()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  const handleRequest = async (e: React.FormEvent<HTMLFormElement>): Promise<void> => {
    e.preventDefault()
    setError('')
    setIsLoading(true)
    try {
      const response = await authApi.requestPasswordReset(email.trim())
      setMessage(response.detail)
    } catch (err) {
      setError(errorText(err))
    } finally {
      setIsLoading(false)
    }
  }

  const handleConfirm = async (e: React.FormEvent<HTMLFormElement>): Promise<void> => {
    e.preventDefault()
    setError('')
    if (password !== confirm) {
      setError('The two passwords do not match.')
      return
    }
    setIsLoading(true)
    try {
      const response = await authApi.confirmPasswordReset(token, password)
      setMessage(response.detail)
    } catch (err) {
      setError(errorText(err))
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-[#09090b]">
      <Card className="w-full max-w-md rounded-lg bg-surface">
        <CardHeader className="space-y-4 text-center">
          <div className="flex justify-center">
            <Shield className="h-12 w-12 text-foreground" />
          </div>
          <h1 className="text-2xl font-bold text-foreground">
            {token ? 'Choose a new password' : 'Reset your password'}
          </h1>
        </CardHeader>

        <CardContent>
          {message ? (
            <div className="space-y-4">
              <p role="status" className="rounded bg-green-900/20 p-3 text-sm text-green-400">
                {message}
              </p>
              <Link to="/login" className="block text-center text-sm text-accent underline">
                Back to sign in
              </Link>
            </div>
          ) : token ? (
            <form onSubmit={handleConfirm} className="space-y-4">
              <div className="space-y-2">
                <label htmlFor="new-password" className="block text-sm font-medium text-foreground">
                  New password (at least 12 characters)
                </label>
                <input
                  id="new-password"
                  type="password"
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  minLength={12}
                  required
                  disabled={isLoading}
                  className={INPUT_CLASS}
                />
              </div>
              <div className="space-y-2">
                <label htmlFor="confirm-password" className="block text-sm font-medium text-foreground">
                  Confirm new password
                </label>
                <input
                  id="confirm-password"
                  type="password"
                  autoComplete="new-password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  minLength={12}
                  required
                  disabled={isLoading}
                  className={INPUT_CLASS}
                />
              </div>
              {error && (
                <div role="alert" className="rounded bg-red-900/20 p-3 text-sm text-red-400">
                  {error}
                </div>
              )}
              <Button type="submit" disabled={isLoading} className="w-full">
                {isLoading ? 'Saving...' : 'Set new password'}
              </Button>
            </form>
          ) : (
            <form onSubmit={handleRequest} className="space-y-4">
              <div className="space-y-2">
                <label htmlFor="reset-email" className="block text-sm font-medium text-foreground">
                  Email
                </label>
                <input
                  id="reset-email"
                  type="email"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  disabled={isLoading}
                  className={INPUT_CLASS}
                />
              </div>
              {error && (
                <div role="alert" className="rounded bg-red-900/20 p-3 text-sm text-red-400">
                  {error}
                </div>
              )}
              <Button type="submit" disabled={isLoading} className="w-full">
                {isLoading ? 'Sending...' : 'Email me a reset link'}
              </Button>
              <Link to="/login" className="block text-center text-sm text-accent underline">
                Back to sign in
              </Link>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
