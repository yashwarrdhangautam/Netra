import { useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { useAuthStore, type User } from '@/stores/authStore'
import { authApi } from '@/api/auth'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Shield } from 'lucide-react'

const INPUT_CLASS =
  'w-full rounded border border-border bg-surface-2 p-3 text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary disabled:cursor-not-allowed disabled:opacity-50'

function messageFor(err: unknown): { text: string; needsMfa: boolean } {
  const response = (err as { response?: { status?: number; data?: { detail?: unknown } } })?.response
  const status = response?.status
  const detail = typeof response?.data?.detail === 'string' ? response.data.detail : ''
  if (detail === 'mfa_required') {
    return { text: 'Enter the 6-digit code from your authenticator app.', needsMfa: true }
  }
  if (detail === 'Invalid MFA code') {
    return { text: 'That code is not valid. Try again or use a backup code.', needsMfa: true }
  }
  if (status === 403 && detail.startsWith('Account locked')) {
    return { text: 'Too many failed attempts. The account is locked for 15 minutes.', needsMfa: false }
  }
  if (status === 401 || status === 422) {
    return { text: 'Invalid email or password.', needsMfa: false }
  }
  if (status === 429) {
    return { text: 'Too many attempts. Wait a few minutes and try again.', needsMfa: false }
  }
  return { text: 'Could not sign in. Check that the NETRA API is running.', needsMfa: false }
}

export function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [needsMfa, setNeedsMfa] = useState(false)
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const navigate = useNavigate()
  const login = useAuthStore((state) => state.login)

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>): Promise<void> => {
    e.preventDefault()
    setError('')
    setIsLoading(true)

    try {
      const response = await authApi.login(email, password, needsMfa ? mfaCode.trim() : undefined)
      if (!response.access_token) {
        setError('Invalid response from server')
        setIsLoading(false)
        return
      }
      const userData = await authApi.getCurrentUser()
      login(response.access_token, { created_at: "", updated_at: "", ...userData } as User)
      await navigate({ to: '/' })
    } catch (err) {
      const { text, needsMfa: mfaNow } = messageFor(err)
      setError(text)
      if (mfaNow) setNeedsMfa(true)
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
          <div>
            <h1 className="text-2xl font-bold text-foreground">
              NETRA <span className="text-base font-normal text-muted-foreground">नेत्र</span>
            </h1>
            <p className="text-sm font-medium text-accent">The Third Eye of Security</p>
            <p className="mt-1 text-xs text-muted-foreground">Unified Cybersecurity Platform</p>
          </div>
        </CardHeader>

        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="email" className="block text-sm font-medium text-foreground">
                Email
              </label>
              <input
                id="email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={isLoading || needsMfa}
                className={INPUT_CLASS}
              />
            </div>

            <div className="space-y-2">
              <label htmlFor="password" className="block text-sm font-medium text-foreground">
                Password
              </label>
              <input
                id="password"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={isLoading || needsMfa}
                className={INPUT_CLASS}
              />
            </div>

            {needsMfa && (
              <div className="space-y-2">
                <label htmlFor="mfa" className="block text-sm font-medium text-foreground">
                  Authenticator code
                </label>
                <input
                  id="mfa"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="123456"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  required
                  disabled={isLoading}
                  className={INPUT_CLASS}
                />
              </div>
            )}

            {error && (
              <div role="alert" className="rounded bg-red-900/20 p-3 text-sm text-red-400">
                {error}
              </div>
            )}

            <Button type="submit" disabled={isLoading} className="w-full">
              {isLoading ? 'Signing in...' : needsMfa ? 'Verify and sign in' : 'Sign in'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
