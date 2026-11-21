import { test, expect, type Page } from '@playwright/test'

// Full-stack QA: sign in, then open every screen and check that it renders and throws no
// uncaught errors. Credentials come from the environment so nothing sensitive is stored here.
//   NETRA_E2E_EMAIL, NETRA_E2E_PASSWORD  (an existing admin account)

const EMAIL = process.env.NETRA_E2E_EMAIL ?? ''
const PASSWORD = process.env.NETRA_E2E_PASSWORD ?? ''
const API = process.env.NETRA_E2E_API_URL ?? 'http://localhost:8001'

const PAGES: { path: string; heading: RegExp }[] = [
  { path: '/', heading: /Dashboard|Risk Score/ },
  { path: '/scans', heading: /Scans/ },
  { path: '/schedules', heading: /Schedules/ },
  { path: '/findings', heading: /Findings/ },
  { path: '/reports', heading: /Reports/ },
  { path: '/compliance', heading: /Compliance/ },
  { path: '/targets', heading: /Targets/ },
  { path: '/attack-graph', heading: /Attack Graph|No Findings|attack/i },
  { path: '/users', heading: /Users/ },
  { path: '/audit', heading: /Audit log/ },
  { path: '/settings', heading: /Settings/ },
  { path: '/bb', heading: /BB Console|NETRA-BB/ },
  { path: '/bb/programs', heading: /Programs/ },
  { path: '/bb/scope', heading: /Scope/ },
  { path: '/bb/hunts', heading: /Hunt Console/ },
  { path: '/bb/triage', heading: /Triage|Findings/ },
  { path: '/bb/submissions', heading: /Submission/ },
  { path: '/bb/graph', heading: /Graph/ },
  { path: '/bb/audit', heading: /Audit log/ },
  { path: '/bb/doctor', heading: /Doctor/ },
  { path: '/bb/settings', heading: /Bug bounty settings/ },
]

async function signIn(page: Page) {
  await page.goto('/login')
  await page.getByLabel('Email').fill(EMAIL)
  await page.getByLabel('Password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).not.toHaveURL(/\/login$/, { timeout: 15_000 })
}

test.describe('NETRA GUI QA', () => {
  test.skip(!EMAIL || !PASSWORD, 'Set NETRA_E2E_EMAIL and NETRA_E2E_PASSWORD to run')

  test('signed-out visitors are sent to the login page with the tagline', async ({ page }) => {
    await page.goto('/bb')
    await expect(page).toHaveURL(/\/login$/)
    await expect(page.getByText('The Third Eye of Security').first()).toBeVisible()
  })

  test('wrong password shows a clear message', async ({ page }) => {
    await page.goto('/login')
    await page.getByLabel('Email').fill('nobody@example.com')
    await page.getByLabel('Password').fill('wrong-password-1')
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page.getByRole('alert')).toContainText('Invalid email or password')
  })

  test('every screen renders without uncaught errors', async ({ page }) => {
    const pageErrors: string[] = []
    page.on('pageerror', (err) => pageErrors.push(`${err.name}: ${err.message}`))

    await signIn(page)
    const broken: string[] = []
    for (const { path, heading } of PAGES) {
      await page.goto(path)
      const text = await page.locator('body').innerText({ timeout: 15_000 }).catch(() => '')
      if (!heading.test(text)) broken.push(path)
    }
    expect(broken, `pages that did not render: ${broken.join(', ')}`).toEqual([])
    expect(pageErrors, pageErrors.join('\n')).toEqual([])
  })

  test('settings: account forms and integrations are real', async ({ page }) => {
    await signIn(page)
    await page.goto('/settings')
    await expect(page.getByRole('heading', { name: 'Change password' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Two-factor sign-in (MFA)' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Personal API key' })).toBeVisible()
    await page.getByRole('tab', { name: 'Integrations' }).click()
    await expect(page.getByText('Shodan API key')).toBeVisible()
    await page.getByRole('tab', { name: 'Notifications' }).click()
    await expect(page.getByRole('button', { name: 'Send email test' })).toBeVisible()
  })

  test('new scan dialog opens from the scans page', async ({ page }) => {
    await signIn(page)
    await page.goto('/scans')
    await page.getByRole('main').getByRole('button', { name: 'New scan' }).click()
    await expect(page.getByRole('heading', { name: 'New scan' })).toBeVisible()
  })

  test('search box shows the empty state for an unknown term', async ({ page }) => {
    await signIn(page)
    await page.goto('/')
    await page.getByRole('searchbox', { name: /Search findings/ }).fill('zz-no-match-qa')
    await expect(page.getByText(/No matches for/)).toBeVisible({ timeout: 10_000 })
  })

  test('reports page has generate controls and history', async ({ page }) => {
    await signIn(page)
    await page.goto('/reports')
    await expect(page.getByRole('heading', { name: 'Generate' })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Generate report' })).toBeDisabled()
    await expect(page.getByRole('heading', { name: 'History' })).toBeVisible()
  })

  test('audit log filters and pages', async ({ page }) => {
    await signIn(page)
    await page.goto('/audit')
    await page.getByLabel('Filter by action').fill('settings')
    await page.getByRole('button', { name: 'Filter' }).click()
    await expect(page.getByText(/of \d+/)).toBeVisible()
  })
})

test.describe('NETRA GUI QA: write flows (cleaned up afterwards by the QA script)', () => {
  test.skip(!EMAIL || !PASSWORD, 'Set NETRA_E2E_EMAIL and NETRA_E2E_PASSWORD to run')

  // Remove what these tests created, even when an assertion failed partway through.
  test.afterAll(async ({ request }) => {
    const login = await request.post(`${API}/api/v1/auth/login`, {
      data: { email: EMAIL, password: PASSWORD },
    })
    if (!login.ok()) return
    const headers = { Authorization: `Bearer ${(await login.json()).access_token}` }

    const targets = await (await request.get(`${API}/api/v1/targets/?per_page=100`, { headers })).json()
    for (const t of targets.items ?? []) {
      if (String(t.name).startsWith('Browser QA target ')) {
        await request.delete(`${API}/api/v1/targets/${t.id}`, { headers })
      }
    }
    const users = await (await request.get(`${API}/api/v1/auth/users`, { headers })).json()
    for (const u of users) {
      if (String(u.email).startsWith('qa-ui-user-')) {
        const removed = await request.delete(`${API}/api/v1/auth/users/${u.id}`, { headers })
        console.log(`cleanup: user ${u.email} -> HTTP ${removed.status()}`)
      }
    }
  })

  test('add a target through the form, with a group', async ({ page }) => {
    const targetName = `Browser QA target ${Date.now()}`
    await signIn(page)
    await page.goto('/targets')
    await page.getByRole('button', { name: 'Add target' }).click()
    await page.getByRole('textbox', { name: 'Name' }).fill(targetName)
    await page.getByRole('combobox', { name: 'Type' }).selectOption('ip')
    await page.getByRole('textbox', { name: 'Value' }).fill('8.8.8.8')
    await page.getByLabel('Group (optional)').fill('browser-qa')
    await page.getByRole('button', { name: 'Add target' }).last().click()
    await expect(page.getByText('Target added.')).toBeVisible({ timeout: 10_000 })
    await expect(page.getByRole('cell', { name: targetName }).first()).toBeVisible()
  })

  test('create a user from the Users page', async ({ page }) => {
    const userEmail = `qa-ui-user-${Date.now()}@example.com`
    await signIn(page)
    await page.goto('/users')
    await page.getByRole('button', { name: 'Add user' }).click()
    await page.getByRole('textbox', { name: 'Email' }).fill(userEmail)
    await page.getByRole('textbox', { name: 'Initial password' }).fill('Ui-User-Pass-2026x')
    await page.getByRole('button', { name: 'Create user' }).click()
    await expect(page.getByText(`${userEmail} created.`)).toBeVisible({ timeout: 10_000 })
    await expect(page.getByRole('cell', { name: userEmail })).toBeVisible()
  })
})
