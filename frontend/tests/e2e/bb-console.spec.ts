import { test, expect } from '@playwright/test'
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

test.beforeEach(async ({ page }) => {
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
