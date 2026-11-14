import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/server'
import { authApi } from './auth'

describe('authApi.login', () => {
  it('returns the token from the login response', async () => {
    server.use(
      http.post('*/api/v1/auth/login', async ({ request }) => {
        const body = (await request.json()) as { email: string }
        expect(body.email).toBe('analyst@example.com')
        return HttpResponse.json({
          access_token: 'token-123',
          token_type: 'bearer',
          user: { id: '1', email: body.email, role: 'analyst' },
        })
      }),
    )
    const result = await authApi.login('analyst@example.com', 'pw-not-used')
    expect(result.access_token).toBe('token-123')
  })

  it('reports an MFA challenge when the server asks for a code', async () => {
    server.use(
      http.post('*/api/v1/auth/login', () =>
        HttpResponse.json({ detail: 'mfa_required' }, { status: 401 }),
      ),
    )
    await expect(authApi.login('mfa@example.com', 'pw-not-used')).rejects.toBeTruthy()
  })
})
