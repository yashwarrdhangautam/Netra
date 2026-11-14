import { test, expect, type Page } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'

const dashboardFixture = {
  active_programs: 0,
  scope_rules: 0,
  assets: 0,
  open_findings: 0,
  submissions_draft: 0,
  out_of_scope_blocks_24h: 0,
  recent_hunts: [],
  doctor: [],
}

const EMAIL = process.env.NETRA_E2E_EMAIL
const PASSWORD = process.env.NETRA_E2E_PASSWORD

// The console sits behind the sign-in guard, so each test signs in first.
async function signIn(page: Page) {
  await page.goto('/login')
  await page.getByLabel('Email').fill(EMAIL ?? '')
  await page.getByLabel('Password').fill(PASSWORD ?? '')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).not.toHaveURL(/\/login$/, { timeout: 15_000 })
}

test.beforeEach(async ({ page }) => {
  test.skip(!EMAIL || !PASSWORD, 'Set NETRA_E2E_EMAIL and NETRA_E2E_PASSWORD to run')
  await signIn(page)
  await page.route('**/api/v1/bb/dashboard', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(dashboardFixture),
    })
  })
})

test('bb console renders core navigation', async ({ page }) => {
  await page.goto('/bb')
  await expect(page.getByText('NETRA-BB Console')).toBeVisible()
  await expect(page.getByText('Scope-first bug bounty operations.')).toBeVisible()
})

test('bb console has no serious axe violations', async ({ page }) => {
  await page.goto('/bb')
  const results = await new AxeBuilder({ page }).analyze()
  const serious = results.violations.filter((item) => ['serious', 'critical'].includes(item.impact || ''))
  expect(serious).toEqual([])
})
